package org.hideprotocol;

/** Base class for every failure this library reports. */
public class HideException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    HideException(String message) {
        super(message);
    }

    /** The data was altered, or is not a HIDE container. */
    public static class Authentication extends HideException {
        private static final long serialVersionUID = 1L;

        Authentication(String message) {
            super(message);
        }
    }

    /**
     * The bytes did not decode at all.
     *
     * <p>A subclass of {@link Authentication} so that code which only cares
     * that something failed is unaffected, while a caller that must tell
     * corruption from forgery can catch this specifically.
     */
    public static final class Malformed extends Authentication {
        private static final long serialVersionUID = 1L;

        Malformed(String message) {
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

    /** The challenge was answered after its window closed. */
    public static final class ChallengeExpired extends HideException {
        private static final long serialVersionUID = 1L;

        ChallengeExpired(String message) {
            super(message);
        }
    }

    /** This answer was already accepted; a genuine signature replayed. */
    public static final class ChallengeReplayed extends HideException {
        private static final long serialVersionUID = 1L;

        ChallengeReplayed(String message) {
            super(message);
        }
    }
}
