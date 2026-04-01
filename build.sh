cd ~/Documents/programmering/python/MEX/dbi/dynamorio/zygisk-module-template
rm -rf module/.cxx
rm -rf module/build
rm -rf build

export ANDROID_HOME=~/android-sdk
#./gradlew :module:assembleRelease --no-build-cache
./gradlew :module:zipRelease