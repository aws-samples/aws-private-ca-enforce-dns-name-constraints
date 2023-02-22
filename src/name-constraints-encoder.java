// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package com.mycompany.app;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;

import lombok.SneakyThrows;



public class generateNameConstraintASN {
  public static void main(String[] args) throws IOException {
    
    String base64EncodedExtValue = getNameConstraintExtensionValue();
    System.out.println(base64EncodedExtValue);
  }

  @SneakyThrows
  private static String getNameConstraintExtensionValue() throws IOException {
    
      // Generate Base64 encoded Nameconstraints extension value
      //GeneralSubtree dnsPrivate = new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".private"));
      //GeneralSubtree dnsLocal = new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".local"));
      //GeneralSubtree dnsCorp = new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".corp"));
      GeneralSubtree dnsSecretCorp = new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".security.example.com"));
      //GeneralSubtree dnsExample = new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".example.com"));
      GeneralSubtree[] permittedSubTree = new GeneralSubtree[] { dnsSecretCorp };
      GeneralSubtree[] excludedSubTree = new GeneralSubtree[] { };
      NameConstraints nameConstraints = new NameConstraints(permittedSubTree, excludedSubTree);

      return new String(Base64.getEncoder().encode(nameConstraints.getEncoded()));
      
     
  }

}
