plugins {
    alias(libs.plugins.agp.lib)
}

android {
    namespace = "com.rosan.hidden_api"
    compileSdk = 37
    compileSdkMinor = 0

    defaultConfig {
        minSdk = 21
    }

    compileOptions {
        targetCompatibility = JavaVersion.VERSION_25
        sourceCompatibility = JavaVersion.VERSION_25
    }
}

dependencies {
}