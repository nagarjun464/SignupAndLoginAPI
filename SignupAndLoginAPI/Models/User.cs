using Google.Cloud.Firestore;

namespace SignupAndLoginAPI.Models
{
    [FirestoreData]
    public class User
    {
        [FirestoreDocumentId]   // Firestore document ID
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [FirestoreProperty]
        public string FirstName { get; set; } = string.Empty;

        [FirestoreProperty]
        public string LastName { get; set; } = string.Empty;

        [FirestoreProperty]
        public string Username { get; set; } = string.Empty;

        [FirestoreProperty]
        public long PhoneNumber { get; set; } 

        [FirestoreProperty]
        public string Email { get; set; } = string.Empty;

        [FirestoreProperty]
        public string PasswordHash { get; set; } = string.Empty;

    }
}
