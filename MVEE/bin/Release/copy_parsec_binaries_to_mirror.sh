cd ~/parsec-2.1
find * | grep "inst$" | xargs -I'{}' cp --parents -R '{}' ~/parsec-2.1-mirror/
cd -
