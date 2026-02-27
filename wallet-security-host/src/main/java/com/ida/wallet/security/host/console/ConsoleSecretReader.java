package com.ida.wallet.security.host.console;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

@Component
public class ConsoleSecretReader {

    public char[] readSecret(String hint) {

        Console console = System.console();

        if (console != null) {
            return console.readPassword(hint);
        }

        // IntelliJ 本地测试 fallback
        try {
            System.out.print(hint);
            BufferedReader br =
                    new BufferedReader(new InputStreamReader(System.in));
            return br.readLine().toCharArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void wipe(char[] data) {
        if (data != null) {
            Arrays.fill(data, '\0');
        }
    }
}
