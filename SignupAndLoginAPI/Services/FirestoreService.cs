using Google.Cloud.Firestore;
using SignupAndLoginAPI.Models;

namespace SignupAndLoginAPI.Services
{
    public class FirestoreService
    {
        private readonly FirestoreDb _db;

        public FirestoreService(IConfiguration config)
        {
            // projectId from appsettings.json or GCP env
            var projectId = config["GoogleCloud:ProjectId"];
            _db = FirestoreDb.Create(projectId);
        }

        public async Task AddUserAsync(User user)
        {
            var collection = _db.Collection("users");
            await collection.Document(user.Id.ToString()).SetAsync(user);
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            var snapshot = await _db.Collection("users")
                .WhereEqualTo("Email", email)
                .Limit(1)
                .GetSnapshotAsync();

            if (snapshot.Count == 0) return null;

            return snapshot.Documents[0].ConvertTo<User>();
        }
    }
}
