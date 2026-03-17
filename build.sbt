name := "joern-trace-extension"
ThisBuild/organization := "io.joern"
ThisBuild/scalaVersion := "3.6.4"

enablePlugins(JavaAppPackaging)

lazy val schema = project.in(file("schema"))
lazy val domainClasses = project.in(file("domain-classes"))
lazy val schemaExtender = project.in(file("schema-extender"))

dependsOn(domainClasses)
libraryDependencies ++= Seq(
  "io.shiftleft" %% "codepropertygraph" % Versions.cpg,
  "io.joern" %% "semanticcpg" % Versions.joern,
  // "io.shiftleft" %% "fuzzyc2cpg-tests" % Versions.cpg % Test classifier "tests",
  "org.scalatest" %% "scalatest" % "3.2.19" % Test,
  "com.lihaoyi" %% "upickle" % "4.1.0",
  "com.github.pathikrit" %% "better-files" % "3.9.2"
)

// Exclude jars already included in main joern distribution
Universal / mappings := (Universal / mappings).value.filterNot {
  case (_, path) => path.contains("org.scala") ||
    path.contains("net.sf.trove4") ||
    path.contains("com.google.guava") ||
    path.contains("org.apache.logging") ||
    path.contains("com.google.protobuf") ||
    path.contains("com.lihaoyi.u") ||
    path.contains("io.shiftleft") ||
    path.contains("org.typelevel") ||
    path.contains("io.undertow") ||    
    path.contains("org.json4s") ||
    path.contains("com.chuusai") ||
    path.contains("io.get-coursier") ||
    path.contains("io.circe") ||
    path.contains("net.java.dev") ||
    path.contains("com.github.javaparser") ||
    path.contains("org.javassist") ||
    // Include classes generated from custom schema via schema-extender
    path.contains("io.joern.schema")
}

lazy val createDistribution = taskKey[Unit]("Create binary distribution of extension")
createDistribution := {
  val pkgBin = (Universal/packageBin).value
  val dstArchive = file("./plugin.zip")
  IO.copyFile(pkgBin, dstArchive,
    CopyOptions(overwrite = true, preserveLastModified = true, preserveExecutable = true))
  println(s"created distribution - resulting files: $dstArchive")
}

ThisBuild/Compile/scalacOptions ++= Seq(
  "-feature",
  "-deprecation",
  "-language:implicitConversions",
)

Global/onChangedBuildSource := ReloadOnSourceChanges

ThisBuild/resolvers ++= Seq(
  Resolver.mavenLocal,
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public")

maintainer := "binarycpg@example.com"
