package eu.europa.esig.dss;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public final class DSSProvider {
    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    private DSSProvider() {}

    private static class SingletonHolder {
        private static final Provider instance;

        static {
            Provider bouncyCastleProviderNewInstance = new BouncyCastleProvider();
            if (Security.addProvider(bouncyCastleProviderNewInstance) == -1) {
                instance = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
            } else {
                instance = bouncyCastleProviderNewInstance;
            }
        }
    }

    public static void init() {
        //noinspection ResultOfMethodCallIgnored
        getInstance();
    }

    public static Provider getInstance() {
        return SingletonHolder.instance;
    }
}
