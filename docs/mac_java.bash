# Source this script on a Mac to properly set up Java environment variables
# Set JAVA_HOME dynamically using Homebrew
export JAVA_HOME="$(brew --prefix openjdk)"

# Use JAVA_HOME consistently for PATH
export PATH="$JAVA_HOME/bin:$PATH"

# Use JAVA_HOME for include paths
export CPPFLAGS="-I$JAVA_HOME/include"
export JNI_CPPFLAGS="-I$JAVA_HOME/include -I$JAVA_HOME/include/darwin"
