package cryptcypher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.util.Scanner;

/**
 * <p>
 * Used to Encrypt and decrypt information.</p>
 *
 * @author Dynisious 03/08/2015
 * @versions 0.0.1
 */
public class CryptCypher {
    private static final Scanner input = new Scanner(System.in);

    /**
     * <p>
     * Prompts the input of information and a key; then encrypts and decrypts
     * the information, validating the process.</p>
     *
     * @param args The command line arguments.
     */
    public static void main(String[] args) throws Exception {
        byte[] randIn;
        double totalStrength = 0; //The sum of all average strengths calculated
        //thus far.
        int iterations = 0; //The number of times the cypher has been used thus far.

        do {
            /*System.out.print("Enter Random Text:- ");
             randIn = input.nextLine().getBytes();*/
            {
                FileInputStream f = new FileInputStream(new File(
                        "C:/CryptCypher/Encrypt.txt"));
                randIn = new byte[(int) (Integer.BYTES * Math.ceil(
                        ((double) f.available()) / Integer.BYTES))];
                f.read(randIn);
            }

            IntBuffer ibuff = ByteBuffer.wrap(randIn).asIntBuffer();
            final int[] plain = new int[ibuff.capacity()];
            ibuff.get(plain);
            System.out.println("\r\nPlaintext:");
            final int[] cPlain = new int[plain.length]; //A copy of plain.
            for (int i = 0; i < plain.length; i++) {
                cPlain[i] = plain[i];
                System.out.println(i + ":- " + plain[i]);
            }
            System.out.print("\r\nEnter Random Text for Key:- ");
            {
                final byte[] temp = input.nextLine().getBytes(); //Get the
                //inputed bytes.
                randIn = new byte[(int) (Math.ceil(((double) temp.length
                        / Integer.BYTES)) * Integer.BYTES)]; //Create an array
                //that is the right length for 
                System.arraycopy(temp, 0, randIn, 0, temp.length);
            }
            ibuff = ByteBuffer.wrap(randIn).asIntBuffer();
            final int[] key = new int[ibuff.capacity()];
            ibuff.get(key);
            System.out.println("Key:");
            for (int i = 0; i < key.length; i++) {
                System.out.println(i + ":- " + key[i]);
            }
            System.out.println("\r\nScramble:");
            int[] scramble = new int[plain.length]; //All indexes of plaintext
            //scrambled.
            {
                int k; //The key to use.
                for (int index = 0; index < plain.length;) { //Loop through each
                    //index in scramble.
                    for (k = 0; k < key.length && index < plain.length; k++) {
                        scramble[index] = key[k] / ++index;
                        //Assign a value to this index.
                    }
                }
            }
            scramble = scrambleIndexes(scramble); //Get the scramble setting for
            //this encryption.
            {
                double strength = 0;
                for (int i = 0; i < scramble.length; i++) {
                    if (i != scramble[i]) { //This index changed.
                        strength++;
                    }
                    System.out.println(i + ":- " + scramble[i]);
                }
                System.out.println("Strength:- " + String.format("%3.2f", 100
                        * strength / scramble.length)
                        + "% index change. Strength=" + String.format("%3.2f",
                                100 * (1 - (2 * Math.abs(
                                        (strength / scramble.length) - 0.5)))) + "%");
            }
            System.out.println("\r\nCyphertext:");
            final int[] cypher = encrypt(plain, key);
            {
                double strength = 0; //The strength of this encryption.
                for (int i = 0; i < cypher.length; i++) {
                    double localStrength = 0; //The cryptographics strength of this
                    //int.
                    {
                        final byte[] bytes1 = ByteBuffer.allocate(
                                Integer.BYTES).putInt(cypher[i]).array();
                        final byte[] bytes2 = ByteBuffer.allocate(
                                Integer.BYTES).putInt(cPlain[i]).array();
                        for (int b = 0; b < Integer.BYTES; b++) { //Loop through
                            //all bytes.
                            int position = 1; //The bit to check for change.
                            for (int p = 0; p < Byte.SIZE; p++) { //Check all bits.
                                if (0 != (position & (bytes1[b] ^ bytes2[b]))) {
                                    //This bit changed
                                    localStrength++;
                                }
                                position <<= position; //Left shift to the next
                                //bit.
                            }
                        }
                    }
                    strength += localStrength; //Add the strength of this byte
                    //to the total.
                    System.out.println(i + ":- " + cypher[i] + " strength="
                            + String.format("%3.2f", 100 * localStrength
                                    / Integer.SIZE) + "% bit change.");
                }
                strength = 100 * strength / (cypher.length * Integer.SIZE);
                totalStrength += strength;
                iterations++; //Increments iterations.
                System.out.println("Strength:- "
                        + String.format("%3.2f", strength) + "% average bit change. Average strength="
                        + String.format("%3.2f", 100
                                - (2 * Math.abs(strength - 50)))
                        + "%\r\nAlgorithm Strength" + iterations + ":- "
                        + String.format("%3.2f", totalStrength / iterations)
                        + "% average bit change. Average strength="
                        + String.format("%3.2f", 100 - (2 * Math.abs(
                                        (totalStrength / iterations) - 50))));
            }

            {
                final FileWriter f = new FileWriter(new File(
                        "C:/CryptCypher/Cypher Output.txt"));
                f.write("");
                for (final int i : cypher) {
                    int position = Integer.rotateRight(1, 1);
                    for (int b = 0; b < Integer.BYTES; b++) {
                        for (int iteration = 0; iteration < Byte.SIZE; iteration++) {
                            if ((i & position) == 0) {
                                f.append("0");
                            } else {
                                f.append("1");
                            }
                            position = Integer.rotateRight(position, 1);
                            //Rotate to the next position.
                        }
                        f.append(" ");
                    }
                    f.append("\r\n");
                }
                f.close();
            }

            System.out.println("\r\nDecyphertext:");
            final int[] decypher = decrypt(cypher, key);
            for (int i = 0; i < plain.length; i++) {
                System.out.println(i + ":- " + decypher[i]
                        + " same as plaintext=" + (cPlain[i] == decypher[i]));
            }

            {
                final FileWriter f = new FileWriter(new File(
                        "C:/CryptCypher/Decyphered Output.txt"));
                f.write("");
                for (final int i : decypher) {
                    int position = Integer.rotateRight(1, 1);
                    for (int b = 0; b < Integer.BYTES; b++) {
                        for (int iteration = 0; iteration < Byte.SIZE; iteration++) {
                            if ((i & position) == 0) {
                                f.append("0");
                            } else {
                                f.append("1");
                            }
                            position = Integer.rotateRight(position, 1);
                            //Rotate to the next position.
                        }
                        f.append(" ");
                    }
                    f.append("\r\n");
                }
                f.close();
            }

            {
                final FileWriter f = new FileWriter(new File(
                        "C:/CryptCypher/Differential Output.txt"));
                f.write("");
                for (int i = 0; i < decypher.length; i++) {
                    final int num = decypher[i] ^ cypher[i];
                    int position = Integer.rotateRight(1, 1);
                    for (int b = 0; b < Integer.BYTES; b++) {
                        for (int iteration = 0; iteration < Byte.SIZE; iteration++) {
                            if ((num & position) == 0) {
                                f.append("0");
                            } else {
                                f.append("1");
                            }
                            position = Integer.rotateRight(position, 1);
                            //Rotate to the next position.
                        }
                        f.append(" ");
                    }
                    f.append("\r\n");
                }
                f.close();
            }
        } while (true);
    }

    /**
     * <p>
     * Returns an array of integers of length <code>seed.length</code>
     * containing all numbers from <code>0 to seed.length - 1</code> in a
     * scrambled order.
     *
     * @param seed The random ints used to scramble the indexes.
     *
     * @return All numbers from <code>0 to seed.length - 1</code> in a
     *         scrambled
     *         order.
     */
    private static int[] scrambleIndexes(final int seed[]) {
        final int[] scrambled = new int[seed.length]; //The array of scrambled
        //indexes.
        Arrays.setAll(scrambled, (int operand) -> {
            return -1;
        }); //Set all values in scrambled to -1 to represent unset positions.
        for (int index = 0; index < seed.length; index++) { //Scramble the order.
            int position = Math.floorMod(seed[index], seed.length); //The index
            //to locate this scrambled index in.
            while (scrambled[position] != -1) { //This scrambled index has already
                //been assigned.
                if (++position == seed.length) { //Increment index while keeping
                    //it within the array bounds.
                    position = 0;
                }
            }
            scrambled[position] = index; //Assign this index.
        }
        return scrambled; //Return the scrambled indexes.
    }

    /**
     * <p>
     * Encrypts plaintext using the passed key integers.</p>
     *
     * @param plaintext The data to be encrypted.
     * @param key       The keys to use for encryption.
     *
     * @return The encrypted cyphertext.
     */
    private static int[] encrypt(final int[] plaintext, final int[] key) {
        if (key == null) { //There's no key.
            throw new NullPointerException(
                    "No key was given for the encryption.");
        } else if (plaintext == null) { //There's no plaintext.
            throw new NullPointerException(
                    "No plaintext was given for the encryption.");
        } else if (key.length == 0) { //Theres no key.
            throw new IndexOutOfBoundsException(
                    "No key was given for the encryption.");
        } else if (plaintext.length == 0) {//There's no plaintext.
            throw new IndexOutOfBoundsException(
                    "No plaintext was given for encryption.");
        }

        {
            final int[] xOred = new int[plaintext.length]; //An array of the
            //xOred ints.
            {
                int k; //The index of the key to use for encryption.
                xOred[0] = plaintext[0] ^ key[0]; //Index 0 in xOred is
                //the key int as it is only encrypted with a key.
                for (int index = 1; index < plaintext.length;) { //Go through
                    //each int to be encrypted.
                    for (k = 0; k < key.length && index < plaintext.length; k++, index++) {
                        //Loop through each key.
                        xOred[index] = plaintext[index]
                                ^ plaintext[index - 1] ^ key[k]; //Encrypt the
                        //int with the key and the previous unencrypted int.
                    }
                }
            }

            int[] scramble = new int[plaintext.length]; //All indexes of
            //plaintext scrambled.
            {
                int k; //The key to use as a base for the scrambled index.
                for (int index = 0; index < plaintext.length;) { //Loop through
                    //each index in scramble.
                    for (k = 0; k < key.length && index < plaintext.length; k++) {
                        scramble[index] = key[k] / ++index; //Assign a value to
                        //this index based off key.
                    }
                }
            }
            scramble = scrambleIndexes(scramble); //Get the scramble setting for
            //this encryption.
            final int[] cyphertext = new int[plaintext.length]; //The encrypted
            //and scrambled ints to return.
            boolean invert = false; //When invert is true the int needs to be
            //inverted.
            for (int i = 0; i < cyphertext.length; i++) { //Scramble plaintext
                //into cyphertext.
                cyphertext[scramble[i]] = invert == false ? xOred[i]
                        : -xOred[i]; //Every second int gets inverted.
                invert = !invert; //Swith invert.
                cyphertext[scramble[i]] = Integer.rotateLeft(
                        cyphertext[scramble[i]], Math.floorMod(i, Integer.SIZE));
                //Each int is left shifted by it's index in plaintext.
            }

            return cyphertext;
        }
    }

    /**
     * <p>
     * Decrypts cyphertext using the passed key integers.</p>
     *
     * @param cyphertext The data to be decrypted.
     * @param key        The keys to use for decryption.
     *
     * @return The decrypted plaintext.
     */
    private static int[] decrypt(final int[] cyphertext, final int[] key) {
        if (key == null) { //There's no key.
            throw new NullPointerException(
                    "No key was given for the decryption.");
        } else if (cyphertext == null) { //There's no cyphertext.
            throw new NullPointerException(
                    "No cyphertext was given for the decryption.");
        } else if (key.length == 0) { //Theres no key.
            throw new IndexOutOfBoundsException(
                    "No key was given for the decryption.");
        } else if (cyphertext.length == 0) {//There's no cyphertext.
            throw new IndexOutOfBoundsException(
                    "No cyphertext was given for decryption.");
        }

        {
            int[] scramble = new int[cyphertext.length]; //All indexes of
            //cyphertext scrambled.
            {
                int k; //The key to use.
                for (int index = 0; index < cyphertext.length;) { //Loop through
                    //each index in scramble.
                    for (k = 0; k < key.length && index < cyphertext.length; k++) {
                        scramble[index] = key[k] / ++index; //Assign a value to
                        //this index.
                    }
                }
            }
            scramble = scrambleIndexes(scramble); //Get the scramble setting for
            //this decryption.

            final int[] xOred = new int[cyphertext.length]; //The unscrambled
            //ints to decrypt.
            boolean invert = false; //When invert is true the int needs to be
            //inverted.
            for (int i = 0; i < xOred.length; i++) { //Uncramble cyphertext
                //into xOred.
                cyphertext[scramble[i]] = Integer.rotateRight(
                        cyphertext[scramble[i]], Math.floorMod(i, Integer.SIZE));
                //Each int is right shifted by it's index in xOred.
                xOred[i] = invert == false ? cyphertext[scramble[i]]
                        : -cyphertext[scramble[i]]; //Every second int gets
                //inverted.
                invert = !invert; //Switch invert.
            }

            final int[] plaintext = new int[cyphertext.length]; //The decrypted
            //ints to return.
            {
                int k; //The index of the key to use for decryption.
                plaintext[0] = xOred[0] ^ key[0]; //Index 0 in xOred is the
                //key int as it is only encrypted with a key.
                for (int index = 1; index < plaintext.length;) { //Go through
                    //each int to be decrypted.
                    for (k = 0; k < key.length && index < plaintext.length; k++, index++) {
                        //Loop through each key.
                        plaintext[index] = xOred[index]
                                ^ plaintext[index - 1] ^ key[k]; //Decrypt the
                        //int with the key and the previous unencrypted int.
                    }
                }
            }

            return plaintext;
        }
    }

}
