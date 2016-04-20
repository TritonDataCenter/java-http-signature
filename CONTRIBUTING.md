# Contributing

We love pull requests from everyone.

Fork, then clone the repo:

    git clone git@github.com:your-username/joyent/java-http-signature.git
    
Make sure all tests including the integration tests pass:

    mvn verify

Make your change. Add tests for your change. Make sure that all tests and style 
checks pass:

    mvn checkstyle:checkstyle -Dcheckstyle.skip=false verify

Add your changes to the CHANGELOG.md and commit.

Push to your fork and [submit a pull request][pr].

[pr]: https://github.com/joyent/java-http-signature/compare/

At this point you're waiting on us. We like to at least comment on pull requests
within three business days (and, typically, one business day). We may suggest
some changes or improvements or alternatives.

Some things that will increase the chance that your pull request is accepted:

* Filing a github issue describing the improvement or the bug before you start work.
* Write tests.
* Follow the style defined in (checkstyle.xml)[checkstyle.xml].
* Write a good commit message.
