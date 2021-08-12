import 'dart:math';
import 'dart:typed_data';
import 'package:ninja_prime/ninja_prime.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/pointycastle.dart';

class JPAKEUtil {
  static const int MAX_ITERATIONS = 1000;

  static BigInt calculateS(String password) {
    return decodeBigInt(Uint8List.fromList(password.codeUnits));
  }

  static Uint8List encodeBigInt(BigInt number) {
    final _byteMask = BigInt.from(0xff);
    // Not handling negative numbers. Decide how you want to do that.
    var size = (number.bitLength + 7) >> 3;
    var result = Uint8List(size);
    for (var i = 0; i < size; i++) {
      result[size - i - 1] = (number & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }

  static BigInt decodeBigInt(Uint8List bytes) {
    var result = BigInt.from(0);
    for (var i = 0; i < bytes.length; i++) {
      result += BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
    }
    return result;
  }

// ignore: slash_for_doc_comments
/**
 * Convert a bytes array to a BigInt
 */

  static BigInt createRandomInRange(BigInt min, BigInt max) {
    var cmp = min.compareTo(max);
    if (cmp >= 0) {
      if (cmp > 0) {
        throw Exception('min may not be bigger than max');
      }
      return min;
    }
    if (min.bitLength > max.bitLength / 2) {
      return createRandomInRange(BigInt.zero, max - min) + min;
    }

    for (var i = 0; i < MAX_ITERATIONS; ++i) {
      var x = randomBigInt(max.bitLength);
      if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0) {
        return x;
      }
    }
    return randomBigInt((max - min).bitLength - 1, random: Random.secure()) +
        min;
  }

  static BigInt getSHA256FromBigInt(BigInt k) {
    final digest = SHA256Digest();
    final byteArray = encodeBigInt(k);
    return decodeBigInt(digest.process(byteArray));
  }

  static BigInt getSha256(ECPoint generator, ECPoint v, ECPoint x, String id) {
    SHA256Digest? digest;

    try {
      digest = SHA256Digest();
      final gbytes = generator.getEncoded();
      final vbytes = v.getEncoded();
      final xbytes = x.getEncoded();
      final idbytes = Uint8List.fromList(id.codeUnits);
      digest.update(gbytes, 0, gbytes.length);
      digest.update(vbytes, 0, vbytes.length);
      digest.update(xbytes, 0, xbytes.length);
      digest.update(idbytes, 0, idbytes.length);
    } catch (e) {
      print(e);
    }

    final output = Uint8List(digest!.digestSize);
    digest.doFinal(output, 0);
    return decodeBigInt(output);
  }
}
