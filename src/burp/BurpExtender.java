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
import javax.swing.*;
import javax.swing.table.*;

public class BurpExtender extends JPanel implements IBurpExtender, ITab, IHttpListener {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private Connection conn;
	private PreparedStatement insertStmt;
	private JTable table = new JTable();
	private JLabel lbDbFile = new JLabel("(no database opened yet)");
	private JTextArea filters = new JTextArea();
	private OutputStream stderr;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("SQLite logger");
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(this);
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
					boolean existed = f.exists();
					connectToDatabase(f.getPath());
					if (existed) refreshTable();
				} catch (Exception e) {
					reportError(e, "Couldn't open database");
				}
			}
		});
		JButton btnRefresh = new JButton("Refresh table");
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
		filters.setRows(3);

		// --------- parent toolbar and main window --------

		toolbar.add(databaseControls);
		toolbar.add(filtersControls);

		setLayout(new BorderLayout());
		add(toolbar, BorderLayout.NORTH);
		add(new JScrollPane(table), BorderLayout.CENTER);
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
		if (messageIsRequest || insertStmt == null) return;
		IHttpService hs = messageInfo.getHttpService();
		IRequestInfo req = helpers.analyzeRequest(messageInfo);
		IResponseInfo resp = helpers.analyzeResponse(messageInfo.getResponse());
		try {
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
		} catch (SQLException se) {
			reportError(se, null);
		}
	}

	void connectToDatabase(final String dbFile) throws IOException,
			SQLException, ClassNotFoundException {
		Class.forName("org.sqlite.JDBC");
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

	void refreshTable() throws SQLException {
		ArrayList<Integer> idList = new ArrayList<>();
		String f = filters.getText();
		try (ResultSet ids = conn.createStatement().executeQuery(
				"SELECT id FROM messages" + (f.isEmpty() ? "" : " WHERE " + f))) {
			while (ids.next()) idList.add(ids.getInt(1));
		}
		idList.trimToSize();
		String[] columns = {"#", "Host", "Method", "URL", "Status", "Length", "MIME type"};

		table.setModel(new AbstractTableModel() {
			@Override public int getRowCount() { return idList.size(); }
			@Override public int getColumnCount() { return columns.length; }

			@Override
			public String getColumnName(int column) {
				return columns[column];
			}

			@Override
			public Object getValueAt(int row, int column) {
				try {
					Integer id = idList.get(row);
					switch (column) {
						case 0: return id;
						case 1: return getMsgString("host", id);
						case 2: return getMsgString("method", id);
						case 3: return getPathFromURL(getMsgString("url", id));
						case 4: return getMsgInt("status_code", id);
						case 5: return getMsgInt("LENGTH(response)", id);
						case 6: return getMsgString("mime_type", id);
					}
				} catch (SQLException e) {
					// reaches return below
				}
				return "";
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

	private String getMsgString(String field, Integer id) throws SQLException {
		try (ResultSet rs = getMsgField(field, id)) {
			return rs.next() ? rs.getString(1) : "";
		}
	}

	private Object getMsgInt(String field, Integer id) throws SQLException {
		try (ResultSet rs = getMsgField(field, id)) {
			return rs.next() ? rs.getInt(1) : "";
		}
	}

	private ResultSet getMsgField(String field, Integer id) throws SQLException {
		PreparedStatement ps = conn.prepareStatement("SELECT " + field + " FROM messages WHERE id = ?");
		ps.setInt(1, id);
		return ps.executeQuery();
	}
}
