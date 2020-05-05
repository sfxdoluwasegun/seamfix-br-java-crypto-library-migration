package com.sf.bioregistra.crypto;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keyczar.Crypter;

import java.nio.file.Path;
import java.nio.file.Paths;

public class CryptoTest {

    @Test
    public void testThatCryptManagerInitializesWithDefaultMap() {
        Path path = Paths.get("src", "test", "resources", "map");
        String mapPath = path.toFile().getAbsolutePath();
        Crypter crypter = Crypto.getInstance(mapPath);
        Assertions.assertThat(crypter).isNotNull();
    }
}
