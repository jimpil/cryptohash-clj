package cryptohash_clj;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

// Public copy of private utilities for BCrypt encoding/decoding
// originally found in OpenBSDBCrypt.java

public class BCryptEncode {
    private static final byte[] decodingTable = new byte[128];
    private static final byte[] encodingTable = // the Bcrypts encoding table for OpenBSD
            {
                    (byte)'.', (byte)'/', (byte)'A', (byte)'B', (byte)'C', (byte)'D',
                    (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J',
                    (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P',
                    (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V',
                    (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b',
                    (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g', (byte)'h',
                    (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
                    (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t',
                    (byte)'u', (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z',
                    (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5',
                    (byte)'6', (byte)'7', (byte)'8', (byte)'9'
            };

    static
    {
        Arrays.fill(decodingTable, (byte) 0xff);
        for (int i = 0; i < encodingTable.length; i++)
        {
            decodingTable[encodingTable[i]] = (byte)i;
        }
    }


    /*
     * encode the input data producing a Bcrypt base 64 String.
     *
     * @param 	a byte representation of the salt or the password
     * @return 	the Bcrypt base64 String
     */
    public static String encodeData(byte[] data)

    {
        if (data.length != 24 && data.length != 16) // 192 bit key or 128 bit salt expected
        {
            throw new DataLengthException("Invalid length: " + data.length + ", 24 for key or 16 for salt expected");
        }
        boolean salt = false;
        if (data.length == 16)//salt
        {
            salt = true;
            byte[] tmp = new byte[18];// zero padding
            System.arraycopy(data, 0, tmp, 0, data.length);
            data = tmp;
        }
        else // key
        {
            data[data.length - 1] = (byte)0;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int len = data.length;

        int a1, a2, a3;
        int i;
        for (i = 0; i < len; i += 3)
        {
            a1 = data[i] & 0xff;
            a2 = data[i + 1] & 0xff;
            a3 = data[i + 2] & 0xff;

            out.write(encodingTable[(a1 >>> 2) & 0x3f]);
            out.write(encodingTable[((a1 << 4) | (a2 >>> 4)) & 0x3f]);
            out.write(encodingTable[((a2 << 2) | (a3 >>> 6)) & 0x3f]);
            out.write(encodingTable[a3 & 0x3f]);
        }

        String result = Strings.fromByteArray(out.toByteArray());
        if (salt == true)// truncate padding
        {
            return result.substring(0, 22);
        }
        else
        {
            return result.substring(0, result.length() - 1);
        }
    }


    /*
     * decodes the bcrypt base 64 encoded SaltString
     *
     * @param 		a 22 character Bcrypt base 64 encoded String
     * @return 		the 16 byte salt
     * @exception 	DataLengthException if the length
     * 				of parameter is not 22
     * @exception 	InvalidArgumentException if the parameter
     * 				contains a value other than from Bcrypts base 64 encoding table
     */
    public static byte[] decodeSaltString(String saltString)
    {
        char[] saltChars = saltString.toCharArray();

        ByteArrayOutputStream out = new ByteArrayOutputStream(16);
        byte b1, b2, b3, b4;

        if (saltChars.length != 22)// bcrypt salt must be 22 (16 bytes)
        {
            throw new DataLengthException("Invalid base64 salt length: " + saltChars.length + " , 22 required.");
        }

        // check String for invalid characters:
        for (int value : saltChars) {
            if (value > 122 || value < 46 || (value > 57 && value < 65)) {
                throw new IllegalArgumentException("Salt string contains invalid character: " + value);
            }
        }

        // Padding: add two '\u0000'
        char[] tmp = new char[22 + 2];
        System.arraycopy(saltChars, 0, tmp, 0, saltChars.length);
        saltChars = tmp;

        int len = saltChars.length;

        for (int i = 0; i < len; i += 4)
        {
            b1 = decodingTable[saltChars[i]];
            b2 = decodingTable[saltChars[i + 1]];
            b3 = decodingTable[saltChars[i + 2]];
            b4 = decodingTable[saltChars[i + 3]];

            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
        }

        byte[] saltBytes = out.toByteArray();

        // truncate:
        byte[] tmpSalt = new byte[16];
        System.arraycopy(saltBytes, 0, tmpSalt, 0, tmpSalt.length);
        saltBytes = tmpSalt;

        return saltBytes;
    }
}
