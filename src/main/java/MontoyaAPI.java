import burp.api.montoya.MontoyaApi;

public final class MontoyaAPI {
    private static MontoyaApi INSTANCE;

    private MontoyaAPI() {}

    public static void initialize(MontoyaApi api){
        if (INSTANCE == null){
            INSTANCE = api;
        }
    }

    public static MontoyaApi getAPI(){
        return INSTANCE;
    }
}