namespace TMF.Auth0.FGA.WebApp.Authorization
{
    public class VerificationRequest
    {
        public TupleKey TupleKey { get; set; }
    }

    public class TupleKey
    {
        public string User { get; set; }
        public string Relation { get; set; }
        public string Object { get; set; }
    }
}
