package io.micronaut.context.env;


import it.unimi.dsi.Util;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;


@State(Scope.Benchmark)
public class RandomNonceBenchmark {
  /**
   * Length of generated CSP nonce values. Must be a multiple of 8.
   */
  public static final int NONCE_LENGTH = 8 * 2;

  private static final Random defaultRandom;
  private static final Random sha1Random;
  private static final Random nativeRandom;
  private static final Random secureRandom;

  public enum StaticAlgorithm {
    XOROSHIRO_128,
    XORSHIFT_2014;

    public byte[] generateBytes() {
      switch (this) {
        case XOROSHIRO_128:
          byte[] randomBytes = new byte[NONCE_LENGTH];
          int iter = 0;
          while (iter < (NONCE_LENGTH / 8)) {
            System.arraycopy(Util.randomSeedBytes(), 0, randomBytes, iter * 8, 8);
            iter++;
          }
          return randomBytes;
      }
      throw new IllegalStateException(
        "Static algorithm not implemented: " + this.name());
    }
  }

  static {
    try {
      defaultRandom = new Random();
      secureRandom = SecureRandom.getInstanceStrong();
      sha1Random = SecureRandom.getInstance("SHA1PRNG");
      nativeRandom = SecureRandom.getInstance("NativePRNG");
    } catch (NoSuchAlgorithmException nsae) {
      throw new RuntimeException(nsae);
    }
  }

  public static void main(String[] args) throws RunnerException {
    Options opt = new OptionsBuilder()
      .include(".*" + RandomNonceBenchmark.class.getSimpleName() + ".*")
      .warmupIterations(3)
      .measurementIterations(5)
      .forks(1)
      .build();

    new Runner(opt).run();
  }

  // Generate a CSP nonce with the provided random tool.
  private byte[] generateCSPNonce(Random random) {
    byte[] randomBytes = new byte[NONCE_LENGTH];
    random.nextBytes(randomBytes);
    return randomBytes;
  }

  // Generate a CSP nonce with the provided random tool, or if `null`, static utils.
  private byte[] generateCSPNonce(StaticAlgorithm algo) {
    return algo.generateBytes();
  }

  @Benchmark
  public void benchmarkDefaultRandom() {
    generateCSPNonce(defaultRandom);
  }

  @Benchmark
  public void benchmarkSHA1Random() {
    generateCSPNonce(sha1Random);
  }

  @Benchmark
  public void benchmarkNativeRandom() {
    generateCSPNonce(nativeRandom);
  }

  @Benchmark
  public void benchmarkSecureRandom() {
    generateCSPNonce(secureRandom);
  }

  @Benchmark
  public void benchmarkXoroshiro128() {
    generateCSPNonce(StaticAlgorithm.XOROSHIRO_128);
  }
}
