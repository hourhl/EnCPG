import sbt._

object Versions {
  val cpg = IO.read(file("cpg-version")).trim
  val joern = IO.read(file("joern-version")).trim
}

object Projects {
  lazy val schema = project.in(file("schema"))
  lazy val domainClasses = project.in(file("domain-classes"))
  lazy val schemaExtender = project.in(file("schema-extender"))
}
