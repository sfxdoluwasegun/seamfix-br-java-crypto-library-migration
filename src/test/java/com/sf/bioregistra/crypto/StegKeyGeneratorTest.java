package com.sf.bioregistra.crypto;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

public class StegKeyGeneratorTest {

    @Test
    public void testThatKeyCanBeGeneratedFromEmbeddedStegFolder() {
        Path path = Paths.get("src","test", "resources", "steg-prep");
        String folder = path.toFile().getAbsolutePath();
        StegKeyGenerator keyGenerator = new StegKeyGenerator(folder,"cipher-key", "R0mTkPTwQVgtOBAFB9fUb!ol@sh");
        Assertions.assertThat(keyGenerator.getKey()).isNotBlank();
    }
}
