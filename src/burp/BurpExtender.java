package burp;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URL;
import java.net.MalformedURLException;
import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

public class BurpExtender extends JPanel implements IBurpExtender, ITab,
	   IHttpListener, IMessageEditorController, ListSelectionListener,
	   IContextMenuFactory, IExtensionStateListener {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private Connection conn;
	private PreparedStatement insertStmt;
	private JTable table = new JTable();
	private JLabel lbDbFile = new JLabel("(no database opened yet)");
	private JTextArea filters = new JTextArea();
	private OutputStream stderr;
	private IMessageEditor requestViewer, responseViewer;
	private JButton btnRefresh = new JButton("Refresh table");
	private final Map<String, PreparedStatement> fieldStmts = new HashMap<>();

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("SQLite logger");
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerExtensionStateListener(this);
		this.helpers = callbacks.getHelpers();
		this.callbacks = callbacks;
		this.stderr = callbacks.getStderr();
		JPanel toolbar = new JPanel();
		toolbar.setLayout(new BoxLayout(toolbar, BoxLayout.PAGE_AXIS));

		// ---------- database controls ---------

		JPanel databaseControls = new JPanel();
		databaseControls.setLayout(new BoxLayout(databaseControls, BoxLayout.LINE_AXIS));
		JButton btnDbSelect = new JButton("Select database");
		btnDbSelect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				JFileChooser fc = new JFileChooser();
				if (fc.showSaveDialog(BurpExtender.this) != JFileChooser.APPROVE_OPTION) return;
				File f = fc.getSelectedFile();
				try {
					connectToDatabase(f.getPath());
					table.setEnabled(true);
					refreshTable();
					btnRefresh.setEnabled(true);
					filters.setEnabled(true);
				} catch (Exception e) {
					reportError(e, "Couldn't open database");
				}
			}
		});
		btnRefresh.setEnabled(false);
		btnRefresh.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				try { refreshTable(); } catch (SQLException e) {
					reportError(e, "Couldn't refresh table from database");
				}
			}
		});
		databaseControls.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		databaseControls.add(new JLabel("Database file: "));
		databaseControls.add(lbDbFile);
		databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
		databaseControls.add(btnDbSelect);
		databaseControls.add(Box.createRigidArea(new Dimension(10, 0)));
		databaseControls.add(btnRefresh);

		// -------- filters controls --------

		JPanel filtersControls = new JPanel();
		filtersControls.setLayout(new BoxLayout(filtersControls, BoxLayout.LINE_AXIS));
		filtersControls.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));
		filtersControls.add(new JLabel("Filters: "));
		filtersControls.add(filters);
		filters.setEnabled(false);
		filters.setRows(3);

		// --------- parent toolbar and main window --------

		toolbar.add(databaseControls);
		toolbar.add(filtersControls);

		// -------- split pane --------

		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		JTabbedPane tabs = new JTabbedPane();
		table.getSelectionModel().addListSelectionListener(this);
		table.addMouseListener(new MouseAdapter() {
			public void mousePressed (MouseEvent e) { if (e.isPopupTrigger()) showTablePopup(e); }
			public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) showTablePopup(e); }
		});
		table.setAutoCreateRowSorter(true);
		table.setEnabled(false);
		splitPane.setTopComponent(new JScrollPane(table));
		splitPane.setBottomComponent(tabs);

		requestViewer = callbacks.createMessageEditor(this, false);
		responseViewer = callbacks.createMessageEditor(this, false);
		tabs.addTab("Request", requestViewer.getComponent());
		tabs.addTab("Response", responseViewer.getComponent());

		setLayout(new BorderLayout());
		add(toolbar, BorderLayout.NORTH);
		add(splitPane, BorderLayout.CENTER);
	}

	@Override
	public java.util.List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Import into SQLite logger");
		if (insertStmt == null) {
			i.setEnabled(false);
		} else {
			i.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent event) {
					int toolFlag = invocation.getToolFlag();
					try {
						conn.setAutoCommit(false);
						for (IHttpRequestResponse message : messages) {
							insertRequestResponse(toolFlag, message);
						}
						conn.commit();
					} catch (SQLException e) {
						try {
							conn.rollback();
						} catch (SQLException ie) {
							reportError(ie, null);
						}
						reportError(e, "Couldn't import selected messages");
					} finally {
						try {
							conn.setAutoCommit(true);
						} catch (SQLException ie) {
							reportError(ie, null);
						}
					}
				}
			});
		}
		return Collections.singletonList(i);
	}

	@Override
	public void extensionUnloaded() {
		disconnectDatabase();
	}

	private void disconnectDatabase() {
		if (insertStmt != null) try { insertStmt.close(); } catch (SQLException e) {}
		for (PreparedStatement ps : fieldStmts.values()) try { ps.close(); } catch (SQLException e) {}
		fieldStmts.clear();
		if (conn != null) try { conn.close(); } catch (SQLException e) {}
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		requestViewer.setMessage(getRequest(), true);
		responseViewer.setMessage(getResponse(), false);
	}

	@Override
	public IHttpService getHttpService() {
		Integer id = getSelectedId();
		if (id == null) return null;
		try (PreparedStatement ps = conn.prepareStatement(
					"SELECT host, port, protocol FROM messages WHERE id = ?")) {
			ps.setInt(1, id);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) return null;
				final String host = rs.getString(1);
				final int port = rs.getInt(2);
				final String protocol = rs.getString(3);
				return new IHttpService() {
					public String getHost() { return host; }
					public int getPort() { return port; }
					public String getProtocol() { return protocol; }
				};
			}
		} catch (SQLException e) {
			reportError(e, null);
			return null;
		}
	}

	@Override
	public byte[] getRequest()  { return getSelectedMsgBytes( "request"); }

	@Override
	public byte[] getResponse() { return getSelectedMsgBytes("response"); }

	private final static String[] REQ_RESP = {"request", "response"};

	private void showTablePopup(MouseEvent e) {
		JPopupMenu pm = new JPopupMenu();
		final int selectedColumn = table.getSelectedColumn();
		final int selectedRow = table.getSelectedRow();
		if (selectedRow == -1) return;
		Column c = columns[table.convertColumnIndexToModel(selectedColumn)];
		if (c.isFilterable()) {
			String columnName = c.name;
			addToPopup(pm, "Show rows with identical " + columnName + " only", new ActionListener() {
				public void actionPerformed(ActionEvent event) {
					c.applyFilter(selectedColumn, selectedRow, false);
				}
			});
			addToPopup(pm, "Hide rows with identical " + columnName, new ActionListener() {
				public void actionPerformed(ActionEvent event) {
					c.applyFilter(selectedColumn, selectedRow, true);
				}
			});
		}
		if (pm.getComponentCount() != 0) pm.addSeparator();
		for (final String rr : REQ_RESP) {
			addToPopup(pm, "Send to Comparer (" + rr + ")", new ActionListener() {
				public void actionPerformed(ActionEvent event) {
					callbacks.sendToComparer(getSelectedMsgBytes(rr));
				}
			});
		}
		pm.show(e.getComponent(), e.getX(), e.getY());
	}

	private static void addToPopup(JPopupMenu pm, String title, ActionListener al) {
		final JMenuItem mi = new JMenuItem(title);
		mi.addActionListener(al);
		pm.add(mi);
	}

	private static void addEquals(Object value, StringBuilder sb, boolean invert) {
		sb.append(invert ? " != " : " = ");
		if (value instanceof String) {
			sb.append('\'').append(escapeSQL(value)).append('\'');
		} else {
			sb.append(value.toString());
		}
	}

	private static String escapeSQL(Object value) {
		return ((String)value).replace("\\", "\\\\").replace("'", "\\'");
	}

	private Integer getSelectedId() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow == -1) return null;
		return (Integer)table.getValueAt(selectedRow, table.convertColumnIndexToView(0));
	}

	private void reportError(Throwable t, String title) {
		if (title != null) JOptionPane.showMessageDialog(this, t.getMessage(),
				title, JOptionPane.ERROR_MESSAGE);
		t.printStackTrace(new PrintStream(stderr));
	}

	@Override public String getTabCaption() { return "SQLite logger"; }
	@Override public Component getUiComponent() { return this; }

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if (!messageIsRequest) {
			try {
				insertRequestResponse(toolFlag, messageInfo);
			} catch (SQLException se) {
				reportError(se, null);
			}
		}
	}

	private void insertRequestResponse(int toolFlag, IHttpRequestResponse messageInfo) throws SQLException {
		if (insertStmt == null) return;
		IHttpService hs = messageInfo.getHttpService();
		IRequestInfo req = helpers.analyzeRequest(messageInfo);
		IResponseInfo resp = helpers.analyzeResponse(messageInfo.getResponse());
		insertStmt.setInt(    1, toolFlag);
		insertStmt.setBytes(  2, messageInfo.getRequest());
		insertStmt.setBytes(  3, messageInfo.getResponse());
		insertStmt.setString( 4, hs.getHost());
		insertStmt.setInt(    5, hs.getPort());
		insertStmt.setString( 6, hs.getProtocol());
		insertStmt.setString( 7, req.getUrl().toString());
		insertStmt.setString( 8, req.getMethod());
		insertStmt.setShort(  9, resp.getStatusCode());
		insertStmt.setString(10, resp.getStatedMimeType());
		insertStmt.setInt(   11, resp.getBodyOffset());
		insertStmt.executeUpdate();
	}

	void connectToDatabase(final String dbFile) throws IOException,
			SQLException, ClassNotFoundException {
		if (conn == null) {
			Class.forName("org.sqlite.JDBC");
		} else {
			disconnectDatabase();
		}
		conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
		conn.setAutoCommit(true); // TODO commit after n messages?
		String fields = "tool, request, response, host, port, protocol, url, " +
			"method, status_code, mime_type, body_offset";
		conn.createStatement().executeUpdate("CREATE TABLE IF NOT EXISTS messages " +
			"(id INTEGER PRIMARY KEY, " + fields + ")");
		insertStmt = conn.prepareStatement("INSERT INTO messages " +
			"(" + fields + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
		lbDbFile.setText(dbFile);
	}

	public final Column[] columns;

	public BurpExtender() {
		// TODO add UI to add/remove columns
		columns = new Column[] {
			new IdColumn("#"),
			new SqlStringColumn("Host", "host"),
			new SqlStringColumn("Method", "method"),
			new SqlPathColumn("URL", "url"),
			new SqlIntegerColumn("Status", "status_code"),
			new SqlIntegerColumn("Length", "LENGTH(response)"),
			new SqlStringColumn("MIME type", "mime_type"),
			new SqlToolColumn("Tool", "tool")
		};
	};

	public abstract class Column {
		public final String name;

		public Column(String name) { this.name = name; }

		public boolean isFilterable() { return true; }

		public void applyFilter(int selectedColumn, int selectedRow, boolean invert) {
			StringBuilder sb = new StringBuilder(filters.getText());
			if (sb.length() > 0) sb.append("\nAND ");
			Object value = table.getValueAt(selectedRow, selectedColumn);
			try {
				addFilterOp(value, sb, invert, selectedRow);
				filters.setText(sb.toString());
				refreshTable();
			} catch (SQLException e) {
				reportError(e, "Couldn't apply filter");
			}
		}

		protected abstract void addFilterOp(Object value, StringBuilder sb,
				boolean invert, int selectedRow) throws SQLException;
		public abstract Object getValue(Integer id) throws SQLException;
		public abstract Class<?> getValueClass();
	}

	public class IdColumn extends Column {
		public IdColumn(String name) { super(name); }

		public boolean isFilterable() { return false; }
		protected void addFilterOp(Object value, StringBuilder sb,
				boolean invert, int selectedRow) {
			throw new UnsupportedOperationException("ID cannot be filtered");
		}

		public Object getValue(Integer id) { return id; }
		public Class<?> getValueClass() { return Integer.class; }
	}

	public abstract class SqlColumn extends Column {
		protected final String field;

		public SqlColumn(String name, String field) {
			super(name);
			this.field = field;
		}

		protected void addFilterOp(Object value, StringBuilder sb,
				boolean invert, int selectedRow) throws SQLException {
			sb.append(field);
			addEquals(value, sb, invert);
		}

		protected String getMsgString(Integer id) throws SQLException {
			try (ResultSet rs = getMsgField(field, id)) {
				return rs.next() ? rs.getString(1) : "";
			}
		}

		protected Object getMsgInt(Integer id) throws SQLException {
			try (ResultSet rs = getMsgField(field, id)) {
				return rs.next() ? rs.getInt(1) : "";
			}
		}
	}

	public class SqlStringColumn extends SqlColumn {
		public SqlStringColumn(String name, String field) { super(name, field); }
		public Object getValue(Integer id) throws SQLException { return getMsgString(id); }
		public Class<?> getValueClass() { return String.class; }
	}

	public class SqlPathColumn extends SqlStringColumn {
		public SqlPathColumn(String name, String field) { super(name, field); }

		public Object getValue(Integer id) throws SQLException {
			return getPathFromURL(getMsgString(id));
		}

		protected void addFilterOp(Object value, StringBuilder sb,
				boolean invert, int selectedRow) {
			sb.append(field).append(invert ? " NOT LIKE '%" : " LIKE '%")
				.append(escapeSQL(value)).append('\'');
		}
	}

	public class SqlToolColumn extends SqlStringColumn {
		public SqlToolColumn(String name, String field) { super(name, field); }

		public Object getValue(Integer id) throws SQLException {
			return callbacks.getToolName((Integer)getMsgInt(id));
		}

		protected void addFilterOp(Object value, StringBuilder sb,
				boolean invert, int selectedRow) throws SQLException {
			addEquals(getMsgInt((Integer)table.getValueAt(selectedRow,
						table.convertColumnIndexToView(0))), sb, invert);
		}
	}

	public class SqlIntegerColumn extends SqlColumn {
		public SqlIntegerColumn(String name, String field) { super(name, field); }
		public Object getValue(Integer id) throws SQLException { return getMsgInt(id); }
		public Class<?> getValueClass() { return Integer.class; }
	}

	void refreshTable() throws SQLException {
		ArrayList<Integer> idList = new ArrayList<>();
		String f = filters.getText();
		try (ResultSet ids = conn.createStatement().executeQuery(
				"SELECT id FROM messages" + (f.isEmpty() ? "" : " WHERE " + f))) {
			while (ids.next()) idList.add(ids.getInt(1));
		}
		idList.trimToSize();

		table.setModel(new AbstractTableModel() {
			@Override public int getRowCount() { return idList.size(); }
			@Override public int getColumnCount() { return columns.length; }
			@Override public String getColumnName(int column) { return columns[column].name; }

			@Override
			public Object getValueAt(int row, int column) {
				try {
					return columns[column].getValue(idList.get(row));
				} catch (SQLException e) {
					// reaches return below
				}
				return "";
			}

			@Override
			public Class<?> getColumnClass(int columnIndex) {
				return columns[columnIndex].getValueClass();
			}
		});
	}

	private static String getPathFromURL(String value) {
		try {
			URL url = new URL(value);
			return url.getPath();
		} catch (MalformedURLException e) {
			return value;
		}
	}

	private static final byte[] EMPTY_BYTE_ARRAY = {};

	private byte[] getSelectedMsgBytes(String field) {
		Integer id = getSelectedId();
		if (id == null) return EMPTY_BYTE_ARRAY;
		try (ResultSet rs = getMsgField(field, id)) {
			return rs.next() ? rs.getBytes(1) : EMPTY_BYTE_ARRAY;
		} catch (SQLException e) {
			reportError(e, null);
			return EMPTY_BYTE_ARRAY;
		}
	}

	private ResultSet getMsgField(String field, Integer id) throws SQLException {
		PreparedStatement ps;
		synchronized (fieldStmts) {
			ps = fieldStmts.get(field);
			if (ps == null) {
				ps = conn.prepareStatement("SELECT " + field + " FROM messages WHERE id = ?");
				fieldStmts.put(field, ps);
			}
		}
		ps.setInt(1, id);
		return ps.executeQuery();
	}
}
