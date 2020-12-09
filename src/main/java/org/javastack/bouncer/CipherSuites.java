package org.javastack.bouncer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class CipherSuites {
	private final String[] protos;
	private final String[] clientSuites;
	private final String[] serverSuites;

	public CipherSuites() throws NoSuchAlgorithmException, IOException {
		final SSLContext ctx = SSLContext.getDefault();
		final SSLParameters sslParams = ctx.getDefaultSSLParameters();

		this.protos = sslParams.getProtocols();
		this.clientSuites = sslParams.getCipherSuites();
		this.serverSuites = sslParams.getCipherSuites();
	}

	public String[] getProtocols() {
		return protos.clone();
	}

	public String[] getClientCipherSuites() {
		return clientSuites.clone();
	}

	public String[] getServerCipherSuites() {
		return serverSuites.clone();
	}
}
