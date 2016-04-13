package com.codiscope.jaks.triggers.java.Ldap;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

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
		
	public void testWebLdapSearchTaintAtIndex1(DirContext ctx, SearchControls searchControls) throws NamingException {
		String searchFilter = "(&(objectClass=group)(objectSid=" + webMethod() + "))";
        NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
        System.out.println(results);
	}
	
	public void testWebTaintAtIndex1() {        
	    Attributes userAttributes = new BasicAttributes("test",  webMethod());	  
	    System.out.println(userAttributes);
	}
	

	String[] ATTRS = { "cn", "mail", "telephonenumber" };
	LDAPConnection ld = new LDAPConnection();

	public void testWebtaintAtIndex2() throws LDAPException {
        ld.search("", ld.SCOPE_SUB, webMethod(), ATTRS, false);
	}
		

	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}




