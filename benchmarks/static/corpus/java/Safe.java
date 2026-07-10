class Safe { void h(java.sql.PreparedStatement ps) throws Exception {
    ps.setString(1, u); ps.executeQuery();               // parameterized
    java.security.MessageDigest.getInstance("SHA-256");  // strong
} }
