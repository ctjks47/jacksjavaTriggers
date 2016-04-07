package com.codiscope.jaks.triggers.java.commandInjection;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.servlet.http.HttpServletRequest;


/*
 Rule:
 <Rule id="CIGITAL-COMMAND-INJECTION-EXEC" lang="java">
 <!-- IMPORTANCE: HIGH -->
 <Category>Command Injection</Category>
 <Title>Use of untrusted data to execute commannds</Title>
 <Description>Runtime.exec() method might be using untrusted data from the user.</Description>
 <Match>
 <QualifiedName><![CDATA[^java\.lang\.Runtime$]]></QualifiedName>
 <Method><![CDATA[^exec$]]></Method>
 <Argument taint="UNTRUSTED">0</Argument>
 </Match>
 <Standards>
 <Standard file="command-injection.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_COMMAND_INJECTION_EXEC {
	HttpServletRequest request = null;
	Runtime rt = Runtime.getRuntime();

	public void testWeb() throws IOException {
		// rt.exec(websource.method1());
		rt.exec(webMethod());
	}
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
	
}
	/* public void testDB() throws IOException {
		// rt.exec(databasesource.method1());
		rt.exec(dbsMethod());
	}

	public void testFile() throws IOException {
		//rt.exec(filesource.method1());
		rt.exec(fsMethod());
	}

	public void testPrivate() throws IOException {
		//rt.exec(privatesource.method1());
		rt.exec(priMethod());
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
	} */

