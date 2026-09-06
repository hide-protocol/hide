package org.hideprotocol;

/** Base class for every failure this library reports. */
public class HideException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    HideException(String message) {
        super(message);
    }

    /** The data was altered, or is not a HIDE container. */
    public static final class Authentication extends HideException {
        private static final long serialVersionUID = 1L;

        Authentication(String message) {
            super(message);
        }
    }

    /** The passphrase is wrong, or the key file was modified. */
    public static final class WrongPassphrase extends HideException {
        private static final long serialVersionUID = 1L;

        WrongPassphrase(String message) {
            super(message);
        }
    }

    /** This key was not one of the recipients. */
    public static final class NoMatchingRecipient extends HideException {
        private static final long serialVersionUID = 1L;

        NoMatchingRecipient(String message) {
            super(message);
        }
    }

    /** The bytes are not a HIDE key. */
    public static final class NotAKey extends HideException {
        private static final long serialVersionUID = 1L;

        NotAKey(String message) {
            super(message);
        }
    }
}
