namespace MountUtility.WPF.Interfaces
{
    public interface ILocalDbUnlocker
    {
        /// Initialize the DB key with the user provided password.
        void InitializeFromPassword(string userPassword);
        bool IsInitialized { get; }
    }
}
