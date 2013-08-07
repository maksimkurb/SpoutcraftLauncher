/*
 * This file is part of Spoutcraft Launcher.
 *
 * Copyright (c) 2011 Spout LLC <http://www.spout.org/>
 * Spoutcraft Launcher is licensed under the Spout License Version 1.
 *
 * Spoutcraft Launcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * In addition, 180 days after any changes are published, you can use the
 * software, incorporating those changes, under the terms of the MIT license,
 * as described in the Spout License Version 1.
 *
 * Spoutcraft Launcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License,
 * the MIT license and the Spout License Version 1 along with this program.
 * If not, see <http://www.gnu.org/licenses/> for the GNU Lesser General Public
 * License and see <http://spout.in/licensev1> for the full license,
 * including the MIT license.
 */
package org.spoutcraft.launcher.security;

/*
 * Copyright 2004 - 2007 University of Cardiff.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * Verifies a signed jar file given an array of truted CA certs
 *
 * @author Andrew Harrison
 * @version $Revision: 148 $
 * @created Apr 11, 2007: 11:02:26 PM
 * @date $Date: 2007-04-12 13:31:48 +0100 (Thu, 12 Apr 2007) $ modified by $Author: scmabh $
 * @todo Put your notes here...
 */


public class JarVerifier {

    @SuppressWarnings("rawtypes")
	public static void verify(JarFile jf, X509Certificate[] trustedCaCerts) throws IOException, CertificateException {
        Vector<JarEntry> entriesVec = new Vector<JarEntry>();

        // Ensure there is a manifest file
        Manifest man = jf.getManifest();
        if (man == null)
            throw new SecurityException("The JAR is not signed");

        // Ensure all the entries' signatures verify correctly
        byte[] buffer = new byte[8192];
        Enumeration entries = jf.entries();

        while (entries.hasMoreElements()) {
            JarEntry je = (JarEntry) entries.nextElement();
            entriesVec.addElement(je);
            InputStream is = jf.getInputStream(je);
            @SuppressWarnings("unused")
			int n;
            while ((n = is.read(buffer, 0, buffer.length)) != -1) {
                // we just read. this will throw a SecurityException
                // if  a signature/digest check fails.
            }
            is.close();
        }
        jf.close();

        // Get the list of signer certificates
        Enumeration e = entriesVec.elements();
        while (e.hasMoreElements()) {
            JarEntry je = (JarEntry) e.nextElement();

            if (je.isDirectory())
                continue;
            // Every file must be signed - except
            // files in META-INF
            Certificate[] certs = je.getCertificates();
            if ((certs == null) || (certs.length == 0)) {
                if (!je.getName().startsWith("META-INF"))
                    throw new SecurityException("The JCE framework " +
                            "has unsigned " +
                            "class files.");
            } else {
                // Check whether the file
                // is signed as expected.
                // The framework may be signed by
                // multiple signers. At least one of
                // the signers must be a trusted signer.

                // First, determine the roots of the certificate chains
                X509Certificate[] chainRoots = getChainRoots(certs);
                boolean signedAsExpected = false;

                for (int i = 0; i < chainRoots.length; i++) {
                    if (isTrusted(chainRoots[i], trustedCaCerts)) {
                        signedAsExpected = true;
                        break;
                    }
                }

                if (!signedAsExpected) {
                    throw new SecurityException("The JAR is not signed by a trusted signer");
                }
            }
        }
    }

    public static boolean isTrusted(X509Certificate cert,
                                     X509Certificate[] trustedCaCerts) {
        // Return true iff either of the following is true:
        // 1) the cert is in the trustedCaCerts.
        // 2) the cert is issued by a trusted CA.

        // Check whether the cert is in the trustedCaCerts
        for (int i = 0; i < trustedCaCerts.length; i++) {
            // If the cert has the same SubjectDN
            // as a trusted CA, check whether
            // the two certs are the same.
            if (cert.getSubjectDN().equals(trustedCaCerts[i].getSubjectDN())) {
                if (cert.equals(trustedCaCerts[i])) {
                    return true;
                }
            }
        }

        // Check whether the cert is issued by a trusted CA.
        // Signature verification is expensive. So we check
        // whether the cert is issued
        // by one of the trusted CAs if the above loop failed.
        for (int i = 0; i < trustedCaCerts.length; i++) {
            // If the issuer of the cert has the same name as
            // a trusted CA, check whether that trusted CA
            // actually issued the cert.
            if (cert.getIssuerDN().equals(trustedCaCerts[i].getSubjectDN())) {
                try {
                    cert.verify(trustedCaCerts[i].getPublicKey());
                    return true;
                } catch (Exception e) {
                    // Do nothing.
                }
            }
        }

        return false;
    }

    public static X509Certificate[] getChainRoots(Certificate[] certs) {
        Vector<X509Certificate> result = new Vector<X509Certificate>(3);
        // choose a Vector size that seems reasonable
        for (int i = 0; i < certs.length - 1; i++) {
            if (!((X509Certificate) certs[i + 1]).getSubjectDN().equals(
                    ((X509Certificate) certs[i]).getIssuerDN())) {
                // We've reached the end of a chain
                result.addElement((X509Certificate) certs[i]);
            }
        }
        // The final entry in the certs array is always
        // a "root" certificate
        result.addElement((X509Certificate) certs[certs.length - 1]);
        X509Certificate[] ret = new X509Certificate[result.size()];
        result.copyInto(ret);

        return ret;
    }
}