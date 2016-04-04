package com.codiscope.jaks.triggers.java.commandInjection;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;


/*
 Rule:
 <Rule id="CIGITAL-COMMAND_INJECTION_PROCESSBUILDER_CONSTRUCTOR_TAINTED" lang="java">
	<Category>Command Injection</Category>
	<Title>Use of ProcessBuilder where taint is untrusted</Title>
	<Description>
	Identifies when a command is executed using ProcessBuilder
	and the origin of some parts of the command are from
	untrusted sources.
	</Description>
	<Match>
		<QualifiedName><![CDATA[java.lang.ProcessBuilder]]></QualifiedName>
		<Argument taint="WEB|FILE|DB">0</Argument>
	</Match>
	<Standards>
		<Standard file="command-injection.xml">
			<Context>J2EE</Context>
		</Standard>
	</Standards>
</Rule>
 */
public class CIGITAL_COMMAND_INJECTION_PROCESSBUILDER_CONSTRUCTOR_TAINTED {
	HttpServletRequest request = null;
//	DatabaseSource databasesource = new DatabaseSource();
//	FileSource filesource = new FileSource();
//	PrivateSource privatesource = new PrivateSource();
//	WebSource websource = new WebSource();
//	WebSourceCookie webcookie = new WebSourceCookie();
	
	ProcessBuilder pb;
	
	public void testWeb() throws IOException {
		pb = new ProcessBuilder(webMethod1(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod2(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod3(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(webMethod4(), "myArg1", "myArg2");
	}
	
	public void testFile() throws IOException {
		pb = new ProcessBuilder(fsMethod(), "myArg1", "myArg2");
	}
	
	public void testDB() throws IOException {
		pb = new ProcessBuilder(dbsMethod1(), "myArg1", "myArg2");
		
		pb = new ProcessBuilder(dbsmethod2(), "myArg1", "myArg2");
	}
	
	
	public String dbsMethod1() {
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
	
	public String dbsmethod2() {
		ResultSet rs = null;
		Object column1 = null;
		try {
			column1 = rs.getObject(0);
		} catch (SQLException e) {
			//
		}
		return column1.toString();
	}
	
	public String webMethod1() {
		String s01 = request.getRemoteHost();
		return s01;
	}
	public String webMethod2() {
		String[] s01 = request.getParameterValues("abc");
		return s01.toString();
	}
	
	public String webMethod3() {
		Enumeration s01 = request.getParameterNames();
		return s01.toString();
	}
	
	public String webMethod4() {
		Map s01 = request.getParameterMap();
		return s01.toString();
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
}
