//SPDX:MIT
package example.lib.noecho;

/**
 * Refuse to echo text back to the caller.
 */
public class NoEcho {
    /**
     * Return "no" back to the caller.
     *
     * @parameter text The text to ignore.
     * @return The refusal.
     */
    public String noEcho(final String text) {
        return "no";
    }
}
