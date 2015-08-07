package cryptcypher;

import java.io.File;
import java.io.FileInputStream;
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
            System.out.println("\r\nDecyphertext:");
            final int[] decypher = decrypt(cypher, key);
            for (int i = 0; i < plain.length; i++) {
                System.out.println(i + ":- " + decypher[i]
                        + " same as plaintext=" + (cPlain[i] == decypher[i]));
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
        });
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
        return scrambled;
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
            {
                int k; //The index of the key to use for encryption.
                for (int index = 0; index < plaintext.length;) { //Go through
                    //each int to be encrypted.
                    for (k = 0; k < key.length && index < plaintext.length; k++, index++) {
                        //Loop through each key.
                        plaintext[index] = plaintext[index] ^ key[k]; //Encrypt
                        //the int.
                    }
                }
            }
            int[] scramble = new int[plaintext.length]; //All indexes of
            //plaintext scrambled.
            {
                int k; //The key to use.
                for (int index = 0; index < plaintext.length;) { //Loop through
                    //each index in scramble.
                    for (k = 0; k < key.length && index < plaintext.length; k++) {
                        scramble[index] = key[k] / ++index; //Assign a value to
                        //this index.
                    }
                }
            }
            scramble = scrambleIndexes(scramble); //Get the scramble setting for
            //this encryption.
            final int[] cyphertext = new int[plaintext.length]; //The encrypted
            //and scrambled ints to return.
            for (int i = 0; i < cyphertext.length; i++) { //Scramble plaintext
                //into cyphertext.
                cyphertext[scramble[i]] = plaintext[i]; //Left shift the int
                //by it's unscrambled index.
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
            final int[] plaintext = new int[cyphertext.length]; //The decrypted
            //and unscrambled ints to return.
            for (int i = 0; i < plaintext.length; i++) { //Unscramble cyphertext
                //into plaintext.
                plaintext[i] = cyphertext[scramble[i]]; //Right shift the int
                //by it's unscrambled index.
            }

            {
                int k; //The index of the key to use for decryption.
                for (int index = 0; index < plaintext.length;) { //Go through
                    //each int to be decrypted.
                    for (k = 0; k < key.length && index < plaintext.length; k++, index++) {
                        //Loop through each key.
                        plaintext[index] = plaintext[index] ^ key[k]; //Decrypt
                        //the int.
                    }
                }
            }

            return plaintext;
        }
    }

}
