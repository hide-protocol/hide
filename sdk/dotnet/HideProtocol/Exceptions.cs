namespace HideProtocol;

/// <summary>Base class for every failure this library reports.</summary>
public class HideException : Exception
{
    public HideException(string message) : base(message)
    {
    }
}

/// <summary>The data was altered, or is not a HIDE container.</summary>
public sealed class AuthenticationException : HideException
{
    public AuthenticationException(string message) : base(message)
    {
    }
}

/// <summary>The passphrase is wrong, or the key file was modified.</summary>
public sealed class WrongPassphraseException : HideException
{
    public WrongPassphraseException(string message) : base(message)
    {
    }
}

/// <summary>This key was not one of the recipients.</summary>
public sealed class NoMatchingRecipientException : HideException
{
    public NoMatchingRecipientException(string message) : base(message)
    {
    }
}

/// <summary>The bytes are not a HIDE key.</summary>
public sealed class NotAKeyException : HideException
{
    public NotAKeyException(string message) : base(message)
    {
    }
}
