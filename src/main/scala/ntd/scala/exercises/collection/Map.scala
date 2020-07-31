package ntd.scala.exercises.collection

object Map extends App {
  val student = scala.collection.mutable.Map(
    "id" -> 1,
    "name" -> "ntd",
    "age" -> 24
  )

  student += ("age" -> 25)
  println(student)
}
