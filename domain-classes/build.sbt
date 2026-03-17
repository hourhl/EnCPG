name := "joern-trace-extension-domain-classes"

libraryDependencies += "io.shiftleft" %% "codepropertygraph-domain-classes" % Versions.cpg

val generateDomainClasses = taskKey[Seq[File]]("generate overflowdb domain classes for our schema")

Compile / sourceGenerators += Projects.schema / generateDomainClasses

Compile / sourceDirectories += (Projects.schema / target).value / "odb-codegen"
