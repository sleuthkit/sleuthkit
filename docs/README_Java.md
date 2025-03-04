Autopsy requres that SleuthKit be compiled with Java OpenJDK 17 support.


    bash configure --enable-java


## MacOS
To install Java support on MacOS, use:


     brew install openjdk@19
     brew install ant

Then:

    # Set JAVA_HOME dynamically using Homebrew
    export JAVA_HOME="$(brew --prefix openjdk)"

    # Use JAVA_HOME consistently for PATH
    export PATH="$JAVA_HOME/bin:$PATH"

    # Use JAVA_HOME for include paths
    export CPPFLAGS="-I$JAVA_HOME/include"
    export JNI_CPPFLAGS="-I$JAVA_HOME/include -I$JAVA_HOME/include/darwin"

## Ubuntu
To install Java support on Ubuntu, use:

   apt install -y openjdk-17-jdk-headless

Verify installation with:

   update-java-alternatives --list

Then:

   export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
   export CPPFLAGS="-I$JAVA_HOME/include -I$JAVA_HOME/include/linux"
   export JNI_CPPFLAGS="-I$JAVA_HOME/include -I$JAVA_HOME/include/linux"
