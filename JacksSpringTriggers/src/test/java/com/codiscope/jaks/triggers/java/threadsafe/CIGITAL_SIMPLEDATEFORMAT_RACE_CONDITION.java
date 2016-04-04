package com.codiscope.jaks.triggers.java.threadsafe;

import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Date;

/*
 Rule:
 <Rule id="CIGITAL-SIMPLEDATEFORMAT-RACE-CONDITION" lang="java">
 <Category>Race Condition</Category>
 <Title>Use of SimpleDateFormat class</Title>
 <Description>SimpleDateFormat class is not thread safe.</Description>
 <Match>
 <QualifiedName>java.text.SimpleDateFormat</QualifiedName>
 </Match>
 <Standards>
 <Standard file="java-race-condition-format.xml">
 <Context>J2EE</Context>
 </Standard>
 </Standards>
 </Rule>
 */
public class CIGITAL_SIMPLEDATEFORMAT_RACE_CONDITION {

	public void test() {
		Date date = new Date();

		Format formatter = new SimpleDateFormat("MM/dd/yy");
		String s = formatter.format(date);
		System.out.println(s);
	}
}
