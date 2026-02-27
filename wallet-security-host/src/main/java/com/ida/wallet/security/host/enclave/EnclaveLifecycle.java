package com.ida.wallet.security.host.enclave;

import com.ida.wallet.security.host.console.ConsoleSecretReader;
import lombok.extern.slf4j.Slf4j;
import org.apache.teaclave.javasdk.host.exception.EnclaveCreatingException;
import org.apache.teaclave.javasdk.host.exception.EnclaveDestroyingException;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

@Slf4j
@Component
public class EnclaveLifecycle implements SmartLifecycle {

    private final ConsoleSecretReader reader;
    private final EnclaveService enclaveService;

    private volatile boolean running = false;
    private final AtomicBoolean started = new AtomicBoolean(false);

    public EnclaveLifecycle(ConsoleSecretReader reader, EnclaveService enclaveService) {
        this.reader = reader;
        this.enclaveService = enclaveService;
    }

    @Override
    public void start() {

        // 防止重复启动
        if (!started.compareAndSet(false, true)) {
            return;
        }

        log.info("Creating enclave...");

        try {
            enclaveService.create();
        } catch (EnclaveCreatingException e) {
            throw new IllegalStateException("Failed to create enclave", e);
        }

        log.info("Waiting AES ciphertext input...");

        char[] input = null;
        byte[] cipher = null;

        try {
            input = reader.readSecret("AES ciphertext(Base64): ");

            cipher = decodeBase64(input);

            // Host 只负责传递
            enclaveService.injectCipher(cipher);

            running = true;

            log.info("AES Ciphertext injected into enclave successfully, enclave is running now.");

        } catch (Exception e) {

            log.error("AES Ciphertext injected into enclave failed", e);
            throw new IllegalStateException("AES Ciphertext injected into enclave failed", e);

        } finally {

            if (cipher != null) {
                Arrays.fill(cipher, (byte) 0);
            }

            if (input != null) {
                reader.wipe(input);
            }
        }
    }

    private byte[] decodeBase64(char[] input) {

        byte[] ascii = new byte[input.length];

        for (int i = 0; i < input.length; i++) {
            ascii[i] = (byte) input[i];
        }

        try {
            return Base64.getDecoder().decode(ascii);
        } finally {
            Arrays.fill(ascii, (byte) 0);
        }
    }

    @Override
    public void stop() {
        try {
            enclaveService.destroy();
            running = false;
        } catch (EnclaveDestroyingException e) {
            throw new IllegalStateException("Failed to destroy enclave", e);
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public boolean isAutoStartup() {
        return true;
    }

    /**
     * 最后启动，确保所有Bean就绪
     */
    @Override
    public int getPhase() {
        return Integer.MAX_VALUE;
    }
}
