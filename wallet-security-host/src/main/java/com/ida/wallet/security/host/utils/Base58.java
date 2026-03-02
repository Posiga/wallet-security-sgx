package com.ida.wallet.security.host.utils;

import java.math.BigInteger;

public class Base58 {

    public static final String digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static String encode(byte[] b) {
        StringBuilder sb = new StringBuilder();
        BigInteger n = Binint.b2n(b);
        BigInteger base = BigInteger.valueOf(digits.length());
        while (n.compareTo(BigInteger.ZERO) > 0) {
            BigInteger r = n.mod(base);
            n = n.divide(base);
            sb.append(digits.charAt(r.intValue()));
        }
        for (byte c : b) {
            if (c != 0) break;
            sb.append(digits.charAt(0));
        }
        return sb.reverse().toString();
    }

    public static byte[] decode(String w) {
        BigInteger v = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(digits.length());
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            int index = digits.indexOf(c);
            if (index < 0) throw new IllegalArgumentException("Invalid input");
            v = v.multiply(base).add(BigInteger.valueOf(index));
        }
        byte[] b = Binint.n2b(v);
        int zeros = 0;
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            if (c != digits.charAt(0)) break;
            zeros++;
        }
        if (zeros > 0) {
            byte[] t = new byte[zeros + b.length];
            System.arraycopy(b, 0, t, zeros, b.length);
            b = t;
        }
        return b;
    }
}

class Binint {
    public static BigInteger b2n(byte[] b) {
        if (b.length == 0 || b[0] < 0) {
            byte[] t = new byte[b.length + 1];
            System.arraycopy(b, 0, t, 1, b.length);
            b = t;
        }
        return new BigInteger(b);
    }

    public static byte[] n2b(BigInteger n) {
        return n2b(n, 0);
    }

    public static byte[] n2b(BigInteger n, int length) {
        if (n.compareTo(BigInteger.ZERO) < 0) throw new IllegalArgumentException("Negative number");
        byte[] b = n.toByteArray();
        if (b[0] == 0) {
            byte[] t = new byte[b.length - 1];
            System.arraycopy(b, 1, t, 0, t.length);
            b = t;
        }
        if (length > b.length) {
            byte[] t = new byte[length];
            System.arraycopy(b, 0, t, length - b.length, b.length);
            b = t;
        }
        return b;
    }
}
