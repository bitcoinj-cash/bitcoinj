/*
 * Copyright 2018 Alberto Vilches
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * @author Alberto Vilches
 * @date 09/05/2018
 */
 package org.bitcoinj.utils;

 import org.bitcoinj.core.Base58;
 import org.junit.Assert;
 import org.junit.Test;

 public class Base58Test {

     @Test
     public void basicTest() {

         // Got from https://asecuritysite.com/encryption/base58
         checkBase58("Cn8eVZg", "hello".getBytes());
         checkBase58("xd6H8Cvasm53LmcAPsiBKBayQqHLahXnP2ewxWYtoghaDgjvkxKiMbSTSSqGzzDH",
                 "sd91082309u09ajsdaoisdjas0891237120u3oijasdkasd".getBytes()); // Got from https://asecuritysite.com/encryption/base58

         // Got from Java original class
         checkBase58("Gs3ZDiYqa2BVK9hhs1i1fg61mcws5HmZ1sQxD92ViLmKg9kAWQNw2fohrHnofLCHzjEDzJ2Shhjgt7mmSp421zEHxVaXmTDUbPSqXJprWb8wnT31y5Ua4Y2qw9DtvgNKx4x3hCjsvwCoo1FbDp6hxp2H6csge9kooXk8HUGwUk6LKN2BgraAe9jsvuxMuowCHe1rZRdHFQ4rghi3qFQPPLMxsLguNDKG7cdct8Td5f6jTzdxtwvdoGoXjWL55sa67eQwPGk9MaH8Jkn24jgNMirKkKxLyU5SN6RZmvMbXgSvrRo8Co231Akwax6FthDJM79taXzVPPvbMz4e8KjLiqQzmphjqZ8L5Jjf1RtwtptfqCm9Km456Cae2nggojoeDhJivv7t4jkdnq6VUbarhfvi3KiHc73zJvJYzqvYcp1kuAUuZYdX7voQUGhngqu4A8iUeVDC9GrKAktNFAGe5B66HcuTv7kPwdFHyyJ1mj6t1rHCT8WjyQCuLcjgeen8QeYLZjdEmRPErqimradUyMRJ5P3X1KzBm4orekTWYgYuVqaFRPSm", ("Abstract. A purely peer-to-peer version of electronic cash would allow online\n" +
                 "payments to be sent directly from one party to another without going through a\n" +
                 "financial institution. Digital signatures provide part of the solution, but the main\n" +
                 "benefits are lost if a trusted third party is still required to prevent double-spending.\n" +
                 "We propose a solution to the double-spending problem using a peer-to-peer network.").getBytes());
         checkBase58("1", (new byte[]{0}));
         checkBase58("2", (new byte[]{1}));
         checkBase58("3", (new byte[]{2}));
         checkBase58("A", (new byte[]{9}));
         checkBase58("B", (new byte[]{10}));
         checkBase58("11", (new byte[]{0, 0}));
         checkBase58("12", (new byte[]{0, 1}));
         checkBase58("1111", (new byte[]{0, 0, 0, 0}));
         checkBase58("1112", (new byte[]{0, 0, 0, 1}));
         checkBase58("2MY5SCo", (new byte[]{12, 0, 120, 127, -128}));
         checkBase58("5QuvYAFzNRRL9jbaqnE", (new byte[]{12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7}));
         checkBase58("11115QuvYAFzNRRL9jbaqnE", (new byte[]{0, 0, 0, 0, 12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7}));
         checkBase58("11112a56Pgf6uysSvfzVZ2NYeaFZgeT1RfoNfUUbjCq2LqLpbzn3sYUGcbYz1z5B3J5ZXUNX2NUUup9RzYp2D3fzdrTRhQy1G", (new byte[]{0, 0, 0, 0, 12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7, 0, 0, 0, 0, 12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7, 0, 0, 0, 0, 12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7, 0, 0, 0, 0, 12, 0, 120, 127, -128, 80, 23, 65, 87, 118, 119, 1, 6, 7}));

     }

     private void checkBase58(String expected, byte[] input) {
         String result = Base58.encode(input);
         Assert.assertEquals(expected, result);
         Assert.assertArrayEquals(input, Base58.decode(result));
     }


 }
