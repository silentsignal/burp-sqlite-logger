package burp;

import java.io.*;
import java.sql.DriverManager;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class BurpExtender implements IBurpExtender,/* ITab, TODO implement UI */ IHttpListener {

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PreparedStatement insertStmt;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("SQLite logger");
		//callbacks.addSuiteTab(this); TODO implement UI
		callbacks.registerHttpListener(this);
		this.helpers = callbacks.getHelpers();
		this.callbacks = callbacks;
		try {
			connectToDatabase("/tmp/test.sqlite3"); // TODO implement UI
		} catch (Exception e) { e.printStackTrace(); }
	}

	//@Override public String getTabCaption() { return "SQLite logger"; }
	//@Override public Component getUiComponent() { return null; } // TODO implement UI

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
			se.printStackTrace();
			// TODO use Burp console
		}
	}

	void connectToDatabase(final String dbFile) throws IOException,
			SQLException, ClassNotFoundException {
		Class.forName("org.sqlite.JDBC");
		Connection conn = DriverManager.getConnection("jdbc:sqlite:" + dbFile);
		conn.setAutoCommit(true); // TODO commit after n messages?
		String fields = "tool, request, response, host, port, protocol, url, " +
			"method, status_code, mime_type, body_offset";
		conn.createStatement().executeUpdate("CREATE TABLE IF NOT EXISTS messages " +
			"(id INTEGER PRIMARY KEY, " + fields + ")");
		insertStmt = conn.prepareStatement("INSERT INTO messages " +
			"(" + fields + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	}
}
