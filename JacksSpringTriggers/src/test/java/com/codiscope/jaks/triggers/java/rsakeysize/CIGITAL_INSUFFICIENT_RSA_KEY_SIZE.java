package com.codiscope.jaks.triggers.java.rsakeysize;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
 Rule:
 <Rule lang="java" id="CIGITAL-INSUFFICIENT-RSA-KEY-SIZE">
  <!-- Importance : HIGH -->
  <Category>Weak Encryption</Category>
  <Title>Insufficient Key Size</Title>
  <Description>An otherwise strong encryption algorithm is vulnerable to brute force attack
   when a small key size is used.</Description>
    <Match>
      <QualifiedName>java.security.KeyPairGenerator</QualifiedName>
      <Method>initialize</Method>
      <Argument type="int" comparator="lessThanOrEqual" value="1024">0</Argument>
    </Match>
    <Standards>
      <Standard file="insufficient-key-size.xml">
      	<Context>J2EE</Context>
      </Standard>
    </Standards>
</Rule>
*/
public class CIGITAL_INSUFFICIENT_RSA_KEY_SIZE {

	public void test() throws NoSuchAlgorithmException {
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("");
		kpg.initialize(1024);
	}
}
