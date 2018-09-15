import Foundation

struct CipherFactory {

    private var ciphers: [String: Cipher] = [
        "cesar": CeaserCipher(),
        "alphacesar": AlphanumericCesarCipher(),
        "ftn": FtnCipher(),
        "ftn2": Ftn2Cipher()
    ]

    func cipher(for key: String) -> Cipher {
        return ciphers[key]!
    }
}
