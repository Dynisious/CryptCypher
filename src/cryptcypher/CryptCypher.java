package cryptcypher;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
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
    public static void main(String[] args) {
        int run = 1;
        do {
            System.out.print("Plaintext=");
            ByteBuffer buff = ByteBuffer.wrap(input.nextLine().getBytes());
            final int[] plaintext = new int[buff.limit() / Integer.BYTES];
            for (int i = 0; i < plaintext.length; i++) {
                plaintext[i] = buff.getInt();
            }
            for (int i = 0; i < plaintext.length; i++) {
                plaintext[i] = (int) (Integer.MAX_VALUE * Math.random());
                System.out.println(i + " : " + plaintext[i]);
            }

            System.out.print("\r\nKey=");
            buff = ByteBuffer.wrap(input.nextLine().getBytes());
            final int[] key1 = new int[buff.limit() / Integer.BYTES];
            final int[] key2 = new int[key1.length];
            for (int i = 0; i < key1.length; i++) {
                key1[i] = key2[i] = buff.getInt();
                System.out.println(i + " : " + key1[i]);
            }

            System.out.println("\r\nScramble");
            final int[] scramble = scrambleIndexes(key2[0]);
            for (int i = 0; i < scramble.length; i++) {
                System.out.println(i + " : " + scramble[i]);
            }

            System.out.println("\r\nCyphertext:");
            final int[] cyphertext = encrypt(plaintext, key1);
            double totalChange = 0;
            for (int i = 0; i < cyphertext.length; i++) {
                double change = (i >= plaintext.length) ? -1 : 100.0 * Integer.bitCount(
                        cyphertext[i] ^ plaintext[i]) / Integer.SIZE;
                totalChange += change == -1 ? 0 : change; //Add the change to the total.
                System.out.println(i + " : " + cyphertext[i] + " %change="
                        + (change == -1 ? "N/A strength=N/A"
                                : String.format("%-3.2f%% strength=%-3.2f%%",
                                        change,
                                        100 * (1 - (Math.abs(change - 50) / 50)))));
            }
            totalChange /= plaintext.length; //Get the average change.
            System.out.println("total %change=" + String.format(
                    "%-3.2f%% strength=%-3.2f%%", totalChange,
                    100 * (1 - (Math.abs(
                            totalChange - 50) / 50))));

            System.out.println("\r\nDecyphered:");
            final int[] decyphered = decrypt(cyphertext, key2);
            for (int i = 0; i < decyphered.length; i++) {
                System.out.println(i + " : " + decyphered[i] + " same="
                        + (plaintext[i] == decyphered[i]));
            }

            final int[] differential = new int[plaintext.length];
            for (int i = 0; i < differential.length; i++) {
                differential[i] = plaintext[i] ^ cyphertext[i];
            }
            saveToFile(differential, "differential" + run++ + ".txt");
            System.out.println("\r\nType \"n\" to stop the application.");
        } while (!input.nextLine().equalsIgnoreCase("n"));
    }

    public static int[] scrambleIndexes(int key) {
        int[] scramble = new int[Byte.SIZE]; //The scrambling to apply to
        //the ints of plaintext.
        for (int i = 1; i < scramble.length; i++) {
            scramble[i] = i; //Assign the index to each initial index.
        }
        for (final byte b : ByteBuffer.allocate(Integer.BYTES).putInt(key).array()) {
            final int[] indexes = new int[scramble.length]; //The new scrambled
            //indexes.
            int ones = 0; //The position to place the index for the next 1 found.
            int zeros = Integer.bitCount(Byte.toUnsignedInt(b)); //The position
            //to place the next 0 found.
            int bitCheck = 1;
            for (int i = 0; i < scramble.length; i++, bitCheck = bitCheck << 1) {
                //Go through each bit.
                if ((bitCheck & b) == 0) { //There's a 0 here.
                    indexes[zeros] = scramble[i];
                    zeros++;
                } else { //There's a 1 here.
                    indexes[ones] = scramble[i];
                    ones++;
                }
            }
            scramble = indexes; //Set the newly scrambled indexes.
        }
        return scramble;
    }

    public static int[] encrypt(int[] plaintext, int[] key) {
        if (key.length < 2) {
            throw new IndexOutOfBoundsException(
                    "The key needs to be of at least 2 ints in size.");
        }
        {
            final int[] filledOut = new int[(int) (Byte.SIZE * Math.ceil(
                    (plaintext.length + 1.0) / Byte.SIZE))]; //Fill out the array
            //to be evenly divisable by a byte's size.
            filledOut[0] = plaintext.length; //Put the length of plaintext at
            //the begining of the message.
            System.arraycopy(plaintext, 0, filledOut, 1, plaintext.length);
            if (plaintext.length + 1 != filledOut.length) { //The plaintext is
                //not evenly divisible by the size of an byte.
                //<editor-fold defaultstate="collapsed" desc="Fill out plaintext">
                int seed = 0; //The true random seed for the random number
                //generator.
                for (final int i : key) {
                    seed ^= i;
                }
                for (final int i : plaintext) {
                    seed ^= i;
                }
                final SecureRandom rand = new SecureRandom(ByteBuffer.allocate(
                        Integer.BYTES).putInt(seed).array()); //Create a random
                //number generator with a true random int as a seed.
                for (int i = plaintext.length + 1; i < filledOut.length; i++) {
                    filledOut[i] = Integer.bitCount(
                            key[Math.floorMod(i, key.length)])
                            ^ Integer.bitCount(plaintext[Math.floorMod(i,
                                            plaintext.length)])
                            ^ rand.nextInt(); //Generate a random number to fill
                    //this space.
                }
                //</editor-fold>
            }
            plaintext = filledOut; //Overwrite plaintext with the filled out
            //plaintext.
        }
        {
            final int keyMask = Math.floorDiv(key[0], Integer.bitCount(key[0]));
            for (int i = 0; i < plaintext.length;) {
                for (int k = 1; k < key.length && i < plaintext.length; k++, i++) {
                    plaintext[i] = Integer.rotateLeft(plaintext[i],
                            Integer.bitCount(plaintext[i]));
                    plaintext[i] = plaintext[i] ^ key[k] ^ keyMask; //XOR
                    //plaintext with the key and keyMask to better hide the key.
                    key[k] = key[k] ^ Math.floorDiv(key[k],
                            Integer.bitCount(key[k])); //Change the key's bits
                    //for the next iteration of XORs.
                }
            }
        }
        final int[] indexes = scrambleIndexes(key[0]); //The numbers between 0
        //and 7 in a random order.
        final int[] cyphertext = new int[plaintext.length]; //The XORed and
        //scrambled ints.
        for (int offset = 0; offset < plaintext.length; offset += Byte.SIZE) {
            for (int i = 0; i < indexes.length; i++) {
                cyphertext[offset + i] = plaintext[offset + indexes[i]]; //Scramble the ints.              
            }
        }
        return cyphertext;
    }

    public static int[] decrypt(int[] cyphertext, int[] key) {
        if (key.length < 2) {
            throw new IndexOutOfBoundsException(
                    "The key needs to be of at least 2 ints in size.");
        }
        final int[] indexes = scrambleIndexes(key[0]); //The numbers between 0
        //and 7 in a random order.
        final int[] plaintext = new int[cyphertext.length]; //The
        //unscrambled ints.
        for (int offset = 0; offset < cyphertext.length; offset += Byte.SIZE) {
            for (int i = 0; i < indexes.length; i++) {
                plaintext[offset + indexes[i]] = cyphertext[offset + i];
                //Unscramble the ints.
            }
        }
        {
            final int keyMask = Math.floorDiv(key[0], Integer.bitCount(key[0]));
            for (int i = 0; i < plaintext.length;) {
                for (int k = 1; k < key.length && i < plaintext.length; k++, i++) {
                    plaintext[i] ^= key[k] ^ keyMask; //XOR plaintext with the
                    //key and keyMask reveal the original int.
                    plaintext[i] = Integer.rotateRight(plaintext[i],
                            Integer.bitCount(plaintext[i]));
                    key[k] ^= Math.floorDiv(key[k], Integer.bitCount(key[k]));
                    //Change the key's bits for the next iteration of XORs.
                }
            }
        }
        final int[] message = new int[plaintext[0]]; //The message which was
        //originally encrypted
        try {
            System.arraycopy(plaintext, 1, message, 0, message.length); //Copy the
        } catch (IndexOutOfBoundsException ex) {
            int a = 1;
        }
        //ints from the original message across.
        return message;
    }

    public static void saveToFile(final int[] ints, final String file) {
        try {
            FileWriter w = new FileWriter(file, false);
            w.write("");
            w.close();
            w = new FileWriter(file, true);
            for (final int i : ints) {
                for (final byte b : ByteBuffer.allocate(Integer.BYTES).putInt(i).array()) {
                    int pos = Integer.rotateLeft(1, 7);
                    for (int iteration = 0; iteration < Byte.SIZE; iteration++) {
                        w.write(Integer.toString((b & pos) == 0 ? 0 : 1));
                        pos = Integer.rotateRight(pos, 1);
                    }
                    w.write(" ");
                }
                w.write("\r\n");
            }
            w.close();
        } catch (IOException ex) {
            //Ignore.
        }
    }

}
