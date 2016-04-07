package com.codiscope.jaks.triggers.java.xpathInjection;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;

import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;


/*
 Rule:
 <Rule id="CIGITAL-XPATH-INJECTION-01" lang="java">
 <!-- IMPORTANCE: HIGH -->
 <Category>XPath Injection</Category>
 <Title>Untrusted data to build XPath expression</Title>
 <Description>XPath expression might be constructed using untrusted user input.</Description>
 <Match>
 <QualifiedName><![CDATA[^javax\.xml\.xpath\.XPath$]]></QualifiedName>
 <Method><![CDATA[^compile$]]></Method>
 <Argument taint="UNTRUSTED">0</Argument>
 </Match>
 <Standards>
 <Standard file="xpath-injection.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_XPATH_INJECTION_01 {
	
	HttpServletRequest request = null;

	private XPath getXpath() {
		XPathFactory factory = XPathFactory.newInstance();
		XPath xpath = factory.newXPath();
		return xpath;
	}

	public void testWeb() throws XPathExpressionException {
		XPath xpath = getXpath();
		XPathExpression expr = xpath.compile(webMethod());
	}

	
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}
	/*
	public void testDB() throws XPathExpressionException {
		XPath xpath = getXpath();
		XPathExpression expr = xpath.compile(dbsMethod());
	}

	public void testFile() throws XPathExpressionException {
		XPath xpath = getXpath();
		XPathExpression expr = xpath.compile(fsMethod());
	}

	public void testPrivate() throws XPathExpressionException {
		XPath xpath = getXpath();
		XPathExpression expr = xpath.compile(priMethod());
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
	
	@SuppressWarnings("resource")
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
} */
