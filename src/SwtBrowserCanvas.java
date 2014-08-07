/*
 * This class is made available under the Apache License, Version 2.0.
 *
 * See http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Author: Mark Lee
 *
 * (C)2013 Caprica Software (http://www.capricasoftware.co.uk)
 */


import java.awt.BorderLayout;
import java.awt.Canvas;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JFrame;
import javax.swing.JPanel;

import net.minidev.json.JSONNavi;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.ParseException;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.eclipse.swt.SWT;
import org.eclipse.swt.awt.SWT_AWT;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.browser.LocationEvent;
import org.eclipse.swt.browser.LocationListener;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
/**
 * Implementation of an AWT {@link Canvas} that embeds an SWT {@link Browser} component.
 * <p>
 * With contemporary versions of SWT, the Webkit browser is the default implementation.
 * <p>
 * To embed an SWT component inside of a Swing component there are a number of important
 * considerations (all of which comprise this implementation):
 * <ul>
 *   <li>A background thread must be created to process the SWT event dispatch loop.</li>
 *   <li>The browser component can not be created until after the hosting Swing component (e.g. the
 *       JFrame) has been made visible - usually right after <code>frame.setVisible(true).</code></li>
 *   <li>To cleanly dispose the native browser component, it is necessary to perform that clean
 *       shutdown from inside a {@link WindowListener#windowClosing(WindowEvent)} implementation in
 *       a listener registered on the hosting JFrame.</li>
 *   <li>On Linux, the <code>sun.awt.xembedserver</code> system property must be set.</li>
 * </ul>
 */
public final class SwtBrowserCanvas extends Canvas {

    /**
     * Required for Linux, harmless for other OS.
     * <p>
     * <a href="https://bugs.eclipse.org/bugs/show_bug.cgi?id=161911">SWT Component Not Displayed Bug</a>
     */
    static {
        System.setProperty("sun.awt.xembedserver", "true");
    }

    /**
     * SWT browser component reference.
     */
    private final AtomicReference<Browser> browserReference = new AtomicReference<>();

    /**
     * SWT event dispatch thread reference.
     */
    private final AtomicReference<SwtThread> swtThreadReference = new AtomicReference<>();

    /**
     * Get the native browser instance.
     *
     * @return browser, may be <code>null</code>
     */
    public Browser getBrowser() {
        return browserReference.get();
    }

    /**
     * Navigate to a URL.
     *
     * @param url URL
     */
    public void setUrl(final String url) {
        // This action must be executed on the SWT thread
        getBrowser().getDisplay().asyncExec(new Runnable() {
            @Override
            public void run() {
                getBrowser().setUrl(url);
            }
        });
    }

    /**
     * Create the browser canvas component.
     * <p>
     * This must be called <strong>after</strong> the parent application Frame is made visible -
     * usually directly after <code>frame.setVisible(true)</code>.
     * <p>
     * This method creates the background thread, which in turn creates the SWT components and
     * handles the SWT event dispatch loop.
     * <p>
     * This method will block (for a very short time) until that thread has successfully created
     * the native browser component (or an error occurs).
     *
     * @return <code>true</code> if the browser component was successfully created; <code>false if it was not</code/
     */
    public boolean initialise() {
        CountDownLatch browserCreatedLatch = new CountDownLatch(1);
        SwtThread swtThread = new SwtThread(browserCreatedLatch);
        swtThreadReference.set(swtThread);
        swtThread.start();
        boolean result;
        try {
            browserCreatedLatch.await();
            result = browserReference.get() != null;
        }
        catch (InterruptedException e) {
            e.printStackTrace();
            result = false;
        }
        return result;
    }

    /**
     * Dispose the browser canvas component.
     * <p>
     * This should be called from a {@link WindowListener#windowClosing(WindowEvent)} implementation.
     */
    public void dispose() {
        browserReference.set(null);
        SwtThread swtThread = swtThreadReference.getAndSet(null);
        if (swtThread != null) {
            swtThread.interrupt();
        }
    }

    /**
     * Implementation of a thread that creates the browser component and then implements an event
     * dispatch loop for SWT.
     */
    private class SwtThread extends Thread {

        /**
         * Initialisation latch.
         */
        private final CountDownLatch browserCreatedLatch;

        /**
         * Create a thread.
         *
         * @param browserCreatedLatch initialisation latch.
         */
        private SwtThread(CountDownLatch browserCreatedLatch) {
            this.browserCreatedLatch = browserCreatedLatch;
        }

        @Override
        public void run() {
            // First prepare the SWT components...
            Display display;
            Shell shell;
            try {
                display = new Display();
                shell = SWT_AWT.new_Shell(display, SwtBrowserCanvas.this);
                shell.setLayout(new FillLayout());
                browserReference.set(new Browser(shell, SWT.NONE));
            }
            catch (Exception e) {
                e.printStackTrace();
                return;
            }
            finally {
                // Guarantee the count-down so as not to block the caller, even in case of error -
                // there is a theoretical (rare) chance of failure to initialise the SWT components
                browserCreatedLatch.countDown();
            }
            // Execute the SWT event dispatch loop...
            try {
                shell.open();
                while (!isInterrupted() && !shell.isDisposed()) {
                    if (!display.readAndDispatch()) {
                        display.sleep();
                    }
                }
                browserReference.set(null);
                shell.dispose();
                display.dispose();
            }
            catch (Exception e) {
                e.printStackTrace();
                interrupt();
            }
        }
    }

    /**
     * Example implementation.
     *
     * @param args command-line arguments (unused)
     * @throws OAuthSystemException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws CertificateException
     * @throws IOException
     * @throws ParseException
     */
    public static void main(String[] args) throws OAuthSystemException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, ParseException, IOException {
    	final String clientId= "implicitclient";
    	URL OIDCDiscoveryURL= new URL("http://localhost:3333/core/.well-known/openid-configuration");
    	JSONObject result= (JSONObject)JSONValue.parse(OIDCDiscoveryURL.openStream());

    	JSONNavi<JSONObject> jsonNavi= new JSONNavi<JSONObject>(result.toJSONString());

    	String authorizationEndPoint = (String)jsonNavi.get("authorization_endpoint");
    	URL jwksURL= new URL( (String)jsonNavi.get("jwks_uri") );
    	result= (JSONObject)JSONValue.parse(jwksURL.openStream());
    	jsonNavi= new JSONNavi<JSONObject>(result.toJSONString());
    	String publicKey= (String)(jsonNavi.at("keys").at(0).at("x5c").get(0));
        byte[] res = new Base64(publicKey).decode();
        CertificateFactory certificateFactory= CertificateFactory.getInstance("X.509");
        Certificate cert= certificateFactory.generateCertificate(new ByteArrayInputStream(res));
        final RSAPublicKey pubKey= (RSAPublicKey)cert.getPublicKey();

    	final String state= UUID.randomUUID().toString(); // Not sufficient really, but will do for PoC
    	final OAuthClientRequest request = OAuthClientRequest
    			   .authorizationLocation(authorizationEndPoint)
    			   .setClientId(clientId)
    			   .setRedirectURI("oob://localhost/wpfclient")
    			   .setResponseType("id_token token")
    			   .setScope("openid profile read write")
    			   .setParameter("nonce", UUID.randomUUID().toString())
    			   .setState(state.toString())
    			   .buildQueryMessage();

    	final SwtBrowserCanvas browserCanvas = new SwtBrowserCanvas();

        JPanel contentPane = new JPanel();
        contentPane.setLayout(new BorderLayout());
        contentPane.add(browserCanvas, BorderLayout.CENTER);

        final JFrame frame = new JFrame("SWT Browser Embedded in JPanel");
        frame.setBounds(100, 100, 1195, 795);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setContentPane(contentPane);

        final LocationListener locationListener= new LocationListener() {
			@Override
			public void changing(LocationEvent arg0) {
				if( arg0.location.startsWith("oob://localhost/wpfclient") ) {
					try {
						URI cbURI= new URI(arg0.location);
						String fragment= cbURI.getFragment();
						if( fragment.startsWith("error") ) {
							// ERROR CASE :/
							System.err.println( fragment );
						}
						else {
							Map<String, String> parameters = buildParametersFromFragment(fragment);
							Object cbState= parameters.get("state");
							if( cbState != null && state.equals(cbState) ) {
								String id_token= parameters.get("id_token");

								SignedJWT jwt= SignedJWT.parse(id_token);

								// Verify the signature.
								JWSVerifier verifier = new RSASSAVerifier(pubKey);
								if(jwt.verify(verifier)) {
									ReadOnlyJWTClaimsSet claims= jwt.getJWTClaimsSet();
									if( claims.getAudience().get(0).equals(clientId) ) {
										System.out.println("ALL GOOD!!");
										System.out.println( claims );
									}
									else {
										// ERROR CASE
										System.err.println("Mis-Matched audience identifier!");
									}
								}
								else {
									// ERROR CASE
									System.err.println("VERIFICATION FAILURE for the JWT!");
								}
							}
							else {
								// ERROR CASE
								System.err.println("Mis-Matched State");
							}
						}
					} catch (Exception e) {
						 // ERRO Case :/
						e.printStackTrace();
					}
				}
			}

			@Override
			public void changed(LocationEvent arg0) { }
		};
        frame.addWindowListener(new WindowAdapter() {

            @Override
            public void windowClosing(WindowEvent e) {
           	 Display.getDefault().asyncExec(new Runnable() {
     	        public void run() {
                    // Dispose of the native component cleanly
                	browserCanvas.getBrowser().removeLocationListener(locationListener);
                    browserCanvas.dispose();
     	        }
	     	  });
            }
        });


        frame.setVisible(true);

        // Initialise the native browser component, and if successful...
        if (browserCanvas.initialise()) {
        	 Display.getDefault().asyncExec(new Runnable() {
        	        public void run() {
        	            browserCanvas.getBrowser().addLocationListener(locationListener);
        	            // ...navigate to the desired URL
        	            browserCanvas.setUrl(request.getLocationUri());

        	            frame.setSize(1200, 800);
        	        }
        	  });
        }
        else {
            System.out.println("Failed to initialise browser");
        }
    }

	/**
	 * Converts between a OIDC callback url and a map of parameter names to values.
     *
	 * @param fragment The fragment retrieved from the callback url
	 * @return A dictionary of name -> value
	 */
	private static Map<String, String> buildParametersFromFragment(String fragment) {
		if(fragment.startsWith("#")) {
			fragment= fragment.substring(1);
		}
		String[] parameters= fragment.split("&");
		Map<String, String> parameterValues= new HashMap<String,String>();
		for(String parameter : parameters) {
			String[] parameterValue= parameter.split("=");
			parameterValues.put(parameterValue[0], parameterValue[1]);
		}
		return parameterValues;
	}
}