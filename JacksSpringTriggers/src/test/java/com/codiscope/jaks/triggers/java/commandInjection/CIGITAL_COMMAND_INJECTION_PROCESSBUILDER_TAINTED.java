package com.codiscope.jaks.triggers.java.commandInjection;

import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;

/*
 Rule:
 <Rule id="CIGITAL-COMMAND_INJECTION_PROCESSBUILDER" lang="java">
		<Category>Command Injection</Category>
		<Title>Use of ProcessBuilder where taint is unknown</Title>
		<Description>
			Identifies when a command is executed using ProcessBuilder
			but the origin of some parts of the command are unknown.
		</Description>
		<Match>
			<QualifiedName><![CDATA[java.lang.ProcessBuilder]]></QualifiedName>
			<Method><![CDATA[(command|directory)\b]]></Method>
			<Argument taint="UNTRUSTED">0</Argument>
		</Match>
		<Standards>
			<Standard file="command-injection.xml">
				<Context>J2EE</Context>
			</Standard>
		</Standards>
	</Rule>
 */
public class CIGITAL_COMMAND_INJECTION_PROCESSBUILDER_TAINTED {
//	DatabaseSource databasesource = new DatabaseSource();
//	FileSource filesource = new FileSource();
//	PrivateSource privatesource = new PrivateSource();
//	WebSource websource = new WebSource();
//	WebSourceCookie webcookie = new WebSourceCookie();

	public void test() throws IOException {
		ProcessBuilder pb = new ProcessBuilder("myCommand", "myArg1", "myArg2");
		File file = new File("in.txt");
		
		pb.directory();

		pb.command(dbsMethod1());
		try {
			Process p = pb.start();
		} catch (IOException e) {
			//
		}
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
}
