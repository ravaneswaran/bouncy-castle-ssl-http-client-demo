package demo.rc.http.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;

import demo.rc.http.tls.TLSSocketConnectionFactory;

public class TLSHttpClient implements demo.rc.http.client.HttpClient{

	private static final Logger logger = Logger.getLogger(TLSHttpClient.class.getName());

	public static void main(String[] args) throws Exception {

		String END_POINT = "https://www.one.com/api/users/test@test.com";
		
		logger.info(String.format("Request : %s", END_POINT));
		
		HttpGet httpGet = new HttpGet(END_POINT);
		httpGet.addHeader("Content-Type", "application/json");
		httpGet.addHeader("Authorization",
				"Basic TXlNYXRjaGluZ1N5bmNVc2VyOjFuNzNTdzZ2Tzg4a01tdg==");

		HttpClient httpClient = getHttpClient();
		
		HttpResponse resp = httpClient.execute(httpGet);

		BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
		String inputLine;
		StringBuffer response = new StringBuffer();

		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		
		in.close();
		
		logger.info(String.format("%s : %s", resp.getStatusLine().getStatusCode(), resp.getStatusLine().getReasonPhrase()));
		logger.info(response.toString());
	}

	public static HttpClient getHttpClient() throws Exception {
		SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(
				new TLSSocketConnectionFactory(), new String[] { "TLSv1.2" }, null, new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				});
		
		return HttpClients.custom().setSSLSocketFactory(sslConnectionSocketFactory).build();
	}
}
