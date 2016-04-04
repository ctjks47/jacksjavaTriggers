package com.codiscope.jaks.triggers.java.Ldap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;

import javax.servlet.http.HttpServletRequest;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;


/*
 Rule:
 <Rule id="CIGITAL-JAVA-LDAP-INJECTION-03" lang="java">
 <!-- IMPORTANCE: HIGH -->
 <Category>LDAP Injection</Category>
 <Title>Untrsuted data used to build LDAP query</Title>
 <Description>LDAP search filter might be constructed using untrusted user input.</Description>
 <Match>
 <QualifiedName><![CDATA[^netscape\.ldap\.LDAPConnection$]]></QualifiedName>
 <Method><![CDATA[^search$]]></Method>
 <Argument taint="UNTRUSTED">2</Argument>
 </Match>
 <Standards>
 <Standard file="ldap-injection.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_JAVA_LDAP_INJECTION_03 {
	
	HttpServletRequest request = null;
	

	String[] ATTRS = { "cn", "mail", "telephonenumber" };
	LDAPConnection ld = new LDAPConnection();

	public void testWeb() throws LDAPException {
        ld.search("", ld.SCOPE_SUB, webMethod(), ATTRS, false);
	}
	
	public void testDB() throws LDAPException {
        ld.search("", ld.SCOPE_SUB, dbsMethod(), ATTRS, false);
	}
	
	public void testFile() throws LDAPException {
        ld.search("", ld.SCOPE_SUB, fsMethod(), ATTRS, false);
	}
	
	public void testPrivate() throws LDAPException {
        ld.search("", ld.SCOPE_SUB, priMethod(), ATTRS, false);
	}
	
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
	
	public String dbsMethod() {
		String name = null;
		try {
			ResultSet rs = null;
			while (rs.next()) {
				name = name + rs.getString("Lname");
			}
		} catch (Exception e) {
			//
		}
		return name;
	}
	
	public static String fsMethod() {

		File file = new File("C://test.txt");

		int ch;
		StringBuffer strContent = new StringBuffer("");
		FileInputStream fin = null;
		try {
			fin = new FileInputStream(file);
			ch = fin.read();
			//strContent.append((char) ch);
			strContent.append(Integer.toString(ch));
			//fin.close();
		} catch (FileNotFoundException e) {
			//
		} catch (IOException ioe) {
			//
		}
		return strContent.toString();
	}
	public String priMethod() {
		String s01 = request.getParameter("password");
		return s01;
	}
}
