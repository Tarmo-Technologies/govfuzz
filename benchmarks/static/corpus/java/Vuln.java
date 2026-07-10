class Vuln { void h(String u, java.io.ObjectInputStream ois, java.sql.Statement st) throws Exception {
    Runtime.getRuntime().exec("sh -c " + u);              // EXPECT GF-404
    st.executeQuery("SELECT * FROM t WHERE x=" + u);      // EXPECT GF-419
    Object o = ois.readObject();                          // EXPECT GF-421
    java.security.MessageDigest.getInstance("MD5");       // EXPECT GF-422
    String apiKey = "AKIAsecretvalue1234";                // EXPECT GF-429
} }
