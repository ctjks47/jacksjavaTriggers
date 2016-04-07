package com.codiscope.jaks.triggers.java.Ldap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

/*
 Rule:
 	<Rule id="CIGITAL-JAVA-LDAP-INJECTION-01" lang="java">
		<!-- IMPORTANCE: HIGH -->
		<Category>LDAP Injection</Category>
		<Title>Untrusted data used to build LDAP query</Title>
		<Description>LDAP search filter might be constructed using untrusted user input.</Description>
		<Match>
			<QualifiedName extends="true"><![CDATA[^javax\.naming\.directory\.DirContext$]]></QualifiedName>
			<Method><![CDATA[^search$]]></Method>
			<Argument taint="UNTRUSTED">1</Argument>
		</Match>
		<Standards>
			<Standard file="ldap-injection.xml">
				<Context>J2EE</Context>
			</Standard>
		</Standards>
	</Rule>
 */
public class CIGITAL_JAVA_LDAP_INJECTION_01 {
	HttpServletRequest request = null;
		
	public void testWeb(DirContext ctx, SearchControls searchControls) throws NamingException {
		String searchFilter = "(&(objectClass=group)(objectSid=" + webMthod1() + "))";
        NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
	}
	
	public String webMthod1() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}
/*
	public void testFile(DirContext ctx, SearchControls searchControls) throws NamingException {
		String searchFilter = "(&(objectClass=group)(objectSid=" + fsMethod() + "))";
        NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
	}
	
	public void testDB(DirContext ctx, SearchControls searchControls) throws NamingException {
		String searchFilter = "(&(objectClass=group)(objectSid=" + dbsMethod() + "))";
        NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
	}
	
	public void testPrivate(DirContext ctx, SearchControls searchControls) throws NamingException {
		String searchFilter = "(&(objectClass=group)(objectSid=" + priMethod() + "))";
        NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
	}
	
	public String fsMethod() {

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
	
	public String priMethod() {
		String s01 = request.getParameter("password");
		return s01;
	}
*/
