import io.shiftleft.codepropertygraph.schema._
import flatgraph.codegen.DomainClassesGenerator
import flatgraph.schema.{SchemaBuilder, Property}


import java.io.File

/**
 * CPG Schema Extension for Trace Analysis
 * 
 * Extends the CPG schema with:
 * - TRACE_CALL edge type for dynamic trace function calls
 * - TRACE_DEPTH property for METHOD nodes tracking trace positions
 */
object CpgExtCodegen {
  def main(args: Array[String]): Unit = {
    val outputDir = args.headOption
      .map(new File(_))
      .getOrElse(throw new AssertionError("please pass outputDir as first parameter"))

    if (!outputDir.exists()) {
      outputDir.mkdirs()
    }

    val builder = new SchemaBuilder(
      domainShortName = "Cpg",
      basePackage = "io.shiftleft.codepropertygraph.generated",
      additionalTraversalsPackages = Seq("io.shiftleft")
    )
    val cpgSchema = new CpgSchema(builder)

    // Extension: TRACE_DEPTH property
    // Stores list of depth positions where a method appears in execution trace
    // val traceDepth = builder.addProperty(
    //   name = "TRACE_DEPTH",
    //   valueType = Property.ValueType.Int,
    //   comment = "List of depth positions where method appears in execution trace"
    // ).asList()

    // // Add TRACE_DEPTH property to METHOD nodes
    // cpgSchema.method.method.addProperty(traceDepth)

    val beenTrace = builder.addProperty(
      name = "BeenTraced",
      valueType = Property.ValueType.Boolean,
      comment = "Indicates if the method has been observed in dynamic execution trace"
    )

    // Add TRACE_DEPTH property to METHOD nodes
    cpgSchema.method.method.addProperty(beenTrace)

    // Extension: TRACE_CALL edge type
    // Represents actual function calls observed in dynamic traces
    val traceCallEdge = builder.addEdgeType(
      name = "TRACE_CALL",
      comment = "Edge representing function call observed in dynamic execution trace"
    ).withProperty(cpgSchema.ast.order)
    

    // Connect TRACE_CALL edge: METHOD -> METHOD
    cpgSchema.method.method.addOutEdge(
      edge = traceCallEdge,
      inNode = cpgSchema.method.method
    )

    new DomainClassesGenerator(builder.build).run(outputDir.toPath)
  }
}
