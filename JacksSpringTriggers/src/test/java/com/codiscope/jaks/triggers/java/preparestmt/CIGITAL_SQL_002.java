package com.codiscope.jaks.triggers.java.preparestmt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.servlet.http.HttpServletRequest;


/*
 Rule:
 <Rule id="CIGITAL-SQL-001" lang="java">
 <Category>Dynamic Database Query</Category>
 <Title>Use of java.sql.Statement</Title>
 <Description>
 Identifies dangerous method calls of the java.sql.Statement
 class.
 </Description>
 <Match>
 <QualifiedName>java.sql.Statement</QualifiedName>
 <Method><![CDATA[(executeQuery|executeUpdate|execute|addBatch)\b]]></Method>
 <Argument taint="UNTRUSTED">0</Argument>
 </Match>
 <Standards>
 <Standard file="about-sql-injection.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_SQL_002 {
	
	HttpServletRequest request = null;

	
	private String connString = "jdbc:msql://10.10.10.1:1114/Demo";

	public void test(int accountID) {
		try {
			Connection conn = DriverManager.getConnection(connString, "", "");
			Statement stmt = conn.createStatement();

			stmt.executeQuery("SELECT * FROM Transactions WHERE AccountNum ="
					+ webMethod());
		} catch (Exception e) {
			//
		}
	}
	
	public String webMethod() {
		String s01 = request.getRemoteHost();
		return s01;
	}
}
	
/*	public void test2(int accountID) {
		try {
			Connection conn = DriverManager.getConnection(connString, "", "");
			Statement stmt = conn.createStatement();

			stmt.executeUpdate("update transactions set amount = 1000 WHERE AccountNum ="
					+ fsMethod());
		} catch (Exception e) {
			//
		}
	}
	
	public void test3(int accountID) {
		try {
			Connection conn = DriverManager.getConnection(connString, "", "");
			Statement stmt = conn.createStatement();

			stmt.execute("delete from transactions where AccountNum ="
					+ dbsMethod());
		} catch (Exception e) {
			
		}
	}
	
	public void test4(int accountID) {
		try {
			Connection conn = DriverManager.getConnection(connString, "", "");
			Statement stmt = conn.createStatement();

			stmt.addBatch("insert into transactions(AccountNum) values("
					+ priMethod() + ")");
		} catch (Exception e) {
			//
		}
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
}
*/
