Autopsy requres that SleuthKit be compiled with Java support.


    bash configure --enable-java


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
